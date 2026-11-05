<?php
declare(strict_types=1);

/** Small Symcon lifecycle simulator; no production instance is contacted. */
$GLOBALS['instances'] = []; $GLOBALS['changed'] = []; $GLOBALS['locks'] = [];
class IPSModule
{
    public int $InstanceID;
    public array $attributes = [], $properties = [], $values = [], $buffers = [], $form = [], $timers = [], $positions = [];
    public int $status = 104;
    public function __construct(int $id) { $this->InstanceID = $id; $GLOBALS['instances'][$id] = $this; }
    public function Create(): void { }
    public function ApplyChanges(): void { }
    protected function RegisterAttributeBoolean($k, $v): void { if (!isset($this->attributes[$k])) $this->attributes[$k] = $v; }
    protected function ReadAttributeBoolean($k): bool { return $this->attributes[$k]; }
    protected function WriteAttributeBoolean($k, $v): void { $this->attributes[$k] = $v; }
    protected function RegisterAttributeString($k, $v): void { if (!isset($this->attributes[$k])) $this->attributes[$k] = $v; }
    protected function ReadAttributeString($k): string { return $this->attributes[$k]; }
    protected function WriteAttributeString($k, $v): void { $this->attributes[$k] = $v; }
    protected function RegisterPropertyBoolean($k, $v): void { $this->properties[$k] = $v; }
    protected function RegisterPropertyInteger($k, $v): void { $this->properties[$k] = $v; }
    protected function RegisterPropertyString($k, $v): void { $this->properties[$k] = $v; }
    protected function ReadPropertyBoolean($k): bool { return $this->properties[$k]; }
    protected function ReadPropertyInteger($k): int { return $this->properties[$k]; }
    protected function ReadPropertyString($k): string { return $this->properties[$k]; }
    protected function RegisterVariableBoolean($k, $n, $p, $position): void { $this->values[$k] = false; $this->positions[$k] = $position; }
    protected function RegisterVariableString($k, $n, $p, $position): void { $this->values[$k] = ''; $this->positions[$k] = $position; }
    protected function EnableAction($k): void { }
    protected function RegisterTimer($k, $interval, $script): void { $this->timers[$k] = $interval; }
    protected function RegisterMessage($sender, $message): void { }
    protected function SetTimerInterval($k, $v): void { $this->timers[$k] = $v; }
    protected function SetValue($k, $v): void { $this->values[$k] = $v; }
    protected function GetValue($k) { return $this->values[$k]; }
    protected function SetBuffer($k, $v): void { $this->buffers[$k] = $v; }
    protected function GetBuffer($k): string { return $this->buffers[$k] ?? ''; }
    protected function SetStatus($code): void { $this->status = $code; }
    protected function UpdateFormField($k, $field, $value): void { $this->form[$k][$field] = $value; }
}
function IPS_GetKernelRunlevel(): int { return $GLOBALS['testRunlevel'] ?? 10103; }
function IPS_GetKernelDir(): string { return $GLOBALS['testKernel'] ?? (PHP_OS_FAMILY === 'Windows' ? str_replace('\\', '/', sys_get_temp_dir()) . '/symcon-test-kernel/' : '/var/lib/symcon/'); }
function IPS_HasChanges(int $id): bool { return $GLOBALS['changed'][$id] ?? false; }
function IPS_InstanceExists(int $id): bool { return isset($GLOBALS['instances'][$id]); }
function IPS_GetInstance(int $id): array
{
    return ['InstanceStatus' => $GLOBALS['instances'][$id]->status, 'ModuleInfo' => ['ModuleID' => $GLOBALS['moduleIDs'][$id] ?? '']];
}
function IPS_GetInstanceListByModuleID(string $id): array { return array_keys(array_filter($GLOBALS['moduleIDs'], static fn($value) => $value === $id)); }
function IPS_GetProperty(int $id, string $name) { return $GLOBALS['instances'][$id]->properties[$name]; }
function IPS_SetProperty(int $id, string $name, $value): void { $GLOBALS['instances'][$id]->properties[$name] = $value; }
function IPS_ApplyChanges(int $id): void { $GLOBALS['instances'][$id]->ApplyChanges(); }
function IPS_SemaphoreEnter(string $key, int $ms): bool { if ($GLOBALS['locks'][$key] ?? false) return false; $GLOBALS['locks'][$key] = true; return true; }
function IPS_SemaphoreLeave(string $key): void { $GLOBALS['locks'][$key] = false; }
