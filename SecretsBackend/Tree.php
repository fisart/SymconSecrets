<?php
declare(strict_types=1);
require_once __DIR__ . '/Codec.php';
require_once __DIR__ . '/../SecretsFrontend/Configuration.php';

/** Typed JSON tree: empty objects and arrays, numeric object keys and array indexes stay distinct. */
final class SecretsBackendTree
{
    public static function parse(string $json): array
    {
        return self::parseBounded($json,65536);
    }
    public static function parseBounded(string $json,int $limit): array
    {
        SecretsFrontendConfiguration::decodeBounded('{"value":' . $json . '}', $limit,12); // Server-selected aggregate bound; individual web edits stay at 64 KiB.
        return self::node(json_decode($json, false, 12, JSON_THROW_ON_ERROR));
    }
    private static function node($value): array
    {
        if (is_object($value)) {
            $entries = []; foreach (get_object_vars($value) as $key => $item) { self::name((string)$key); $entries[] = ['key' => (string)$key, 'node' => self::node($item)]; }
            if (count($entries) > 200) throw new InvalidArgumentException('At most 200 children per node.');
            return ['type' => 'object', 'entries' => $entries];
        }
        if (is_array($value)) { if (count($value) > 200) throw new InvalidArgumentException('At most 200 list items.'); return ['type' => 'array', 'items' => array_map([self::class, 'node'], $value)]; }
        return ['type' => $value === null ? 'null' : (is_string($value) ? 'string' : (is_bool($value) ? 'boolean' : (is_int($value) ? 'integer' : 'number'))), 'value' => $value];
    }
    public static function value(array $node)
    {
        if ($node['type'] === 'object') { $object = new stdClass(); foreach ($node['entries'] as $entry) $object->{$entry['key']} = self::value($entry['node']); return $object; }
        if ($node['type'] === 'array') return array_map([self::class, 'value'], $node['items']);
        return $node['value'];
    }
    private static function name(string $name): void
    {
        if ($name === '' || strlen($name) > 160 || str_starts_with($name, '__') || preg_match('/[\x00-\x1f\x7f]/', $name)) throw new InvalidArgumentException('Use a nonempty name without reserved markers or control characters.');
    }
    public static function path(array $path): void
    {
        if (array_values($path) !== $path || count($path) > 12) throw new InvalidArgumentException('Invalid path.');
        foreach ($path as $part) { if (is_string($part)) self::name($part); elseif (!is_int($part) || $part < 0 || $part > 199) throw new InvalidArgumentException('Invalid array index.'); }
    }
    private static function index(array $node, $part): int
    {
        if ($node['type'] === 'object' && is_string($part)) { foreach ($node['entries'] as $i => $entry) if ($entry['key'] === $part) return $i; return -1; }
        if ($node['type'] === 'array' && is_int($part)) return isset($node['items'][$part]) ? $part : -1;
        throw new InvalidArgumentException('Path component has the wrong type.');
    }
    public static function at(array $root, array $path): array
    {
        self::path($path);
        foreach ($path as $part) { $i = self::index($root, $part); if ($i < 0) throw new InvalidArgumentException('Path does not exist.'); $root = $root['type'] === 'object' ? $root['entries'][$i]['node'] : $root['items'][$i]; }
        return $root;
    }
    public static function edit(array &$root, array $path, ?array $value, string $mode): void
    {
        self::path($path);
        if (!$path || !in_array($mode, ['create', 'replace', 'delete'], true)) throw new InvalidArgumentException('Choose an explicit non-root target and operation.');
        $part = array_shift($path); $i = self::index($root, $part);
        if ($path) {
            if ($i < 0) throw new InvalidArgumentException('Parent path does not exist.');
            if ($root['type'] === 'object') self::edit($root['entries'][$i]['node'], $path, $value, $mode);
            else self::edit($root['items'][$i], $path, $value, $mode);
            return;
        }
        if (($mode === 'create' && $i >= 0) || ($mode !== 'create' && $i < 0)) throw new InvalidArgumentException('Target changed; reload the tree.');
        if ($root['type'] === 'object') {
            if ($mode === 'create') $root['entries'][] = ['key' => $part, 'node' => $value];
            elseif ($mode === 'delete') array_splice($root['entries'], $i, 1);
            else $root['entries'][$i]['node'] = $value;
            if (count($root['entries']) > 200) throw new InvalidArgumentException('Too many children.');
        } else {
            if ($mode === 'create') { if ($part !== count($root['items']) || $part >= 200) throw new InvalidArgumentException('Append only at the next array index.'); $root['items'][] = $value; }
            elseif ($mode === 'delete') array_splice($root['items'], $i, 1);
            else $root['items'][$i] = $value;
        }
    }
    public static function listing(array $root, array $path = []): array
    {
        $rows = [['path' => $path, 'type' => $root['type'], 'children' => $root['type'] === 'object' ? count($root['entries']) : ($root['type'] === 'array' ? count($root['items']) : 0)]];
        if ($root['type'] === 'object') foreach ($root['entries'] as $entry) $rows = array_merge($rows, self::listing($entry['node'], array_merge($path, [$entry['key']])));
        elseif ($root['type'] === 'array') foreach ($root['items'] as $i => $child) $rows = array_merge($rows, self::listing($child, array_merge($path, [$i])));
        if (count($rows) > 5000) throw new RuntimeException('Tree listing is too large.');
        return $rows;
    }
    public static function reveal(array $node): array
    {
        $out = [];
        if ($node['type'] === 'object') { foreach ($node['entries'] as $entry) if (!in_array($entry['node']['type'], ['object', 'array'], true)) $out[] = ['field' => $entry['key'], 'value' => $entry['node']['value']]; }
        elseif ($node['type'] === 'array') { foreach ($node['items'] as $i => $item) if (!in_array($item['type'], ['object', 'array'], true)) $out[] = ['field' => $i, 'value' => $item['value']]; }
        else $out[] = ['field' => 'value', 'value' => $node['value']];
        if (strlen(SecretsBackendCodec::json($out)) > 65536) throw new RuntimeException('Record reveal exceeds 64 KiB.');
        return $out;
    }
}
