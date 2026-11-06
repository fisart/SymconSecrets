<?php
declare(strict_types=1);
require_once __DIR__ . '/../Commissioning.php';

$root = sys_get_temp_dir() . '/secrets-path-audit-' . bin2hex(random_bytes(8));
mkdir($root, 0700); mkdir($root . '/same', 0700);
$checks = 0;
$rejectPath = static function (string $vault, string $keys, string $kernel = '/var/lib/symcon/') use (&$checks): void {
    $rejected = false;
    try { SecretsFrontendCommissioning::paths($vault, $keys, $kernel); }
    catch (InvalidArgumentException $e) { $rejected = true; }
    if (!$rejected) throw new RuntimeException('Unsafe storage paths were accepted: ' . $vault . ' | ' . $keys);
    $checks++;
};
try {
    // The auditor's existing-directory, nesting and installation-tree reproductions.
    $rejectPath($root . '/same', $root . '//same');
    $rejectPath($root . '/same/child', $root . '//same');
    $rejectPath('/var//lib/symcon/independent-audit-unused', $root . '/keys');
    // Nonexistent destinations must receive the same comparisons.
    $rejectPath($root . '/new/deep', $root . '//new/deep/');
    $rejectPath($root . '//new', $root . '/new//child');
    $rejectPath('//' . ltrim($root, '/') . '/new', $root . '/new/child');
    $rejectPath($root . '/new/child', $root . '/new////');
    $rejectPath($root . '/kernel//future', $root . '/keys', $root . '//kernel///');
    $rejectPath($root . '/kernel/', $root . '/keys', $root . '//kernel/');
    foreach (['/', '////', 'relative/path', $root . '/./vault', $root . '/../vault', $root . '/bad\\path', $root . "/bad\0path"] as $path) $rejectPath($path, $root . '/keys');
    $good = SecretsFrontendCommissioning::paths('//' . ltrim($root, '/') . '//new-vault///', $root . '/new-keys//', '/var//lib/symcon///');
    if ($good !== ['vaultDirectory' => $root . '/new-vault', 'keyDirectory' => $root . '/new-keys']) throw new RuntimeException('Separate sibling paths were not canonicalized.');
    $checks++;
    // Component-boundary comparisons must permit a sibling with a common prefix.
    SecretsFrontendCommissioning::paths($root . '/kernel-sibling', $root . '/keys', $root . '/kernel'); $checks++;
    file_put_contents($root . '/file', 'not a directory');
    $rejectPath($root . '/file/child', $root . '/keys');
    symlink($root . '/same', $root . '/link');
    $rejectPath($root . '/link/child', $root . '/keys');
    symlink($root . '/missing', $root . '/dangling');
    $rejectPath($root . '/dangling/child', $root . '/keys');
    file_put_contents($root . '/same/data', 'existing');
    $rejectPath($root . '/same', $root . '/keys');
    echo "PASS $checks storage-path alias, nearest-ancestor, separation, kernel, symlink and ordinary-sibling checks\n";
} finally {
    foreach (['link', 'dangling', 'file', 'same/data'] as $name) if (is_link($root . '/' . $name) || is_file($root . '/' . $name)) unlink($root . '/' . $name);
    rmdir($root . '/same'); rmdir($root);
}
