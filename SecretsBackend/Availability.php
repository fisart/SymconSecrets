<?php
declare(strict_types=1);

/** Availability is kept outside the encrypted journal so a locked vault remains observable. */
trait SecretsBackendAvailability
{
    public function GetAvailability(): string
    {
        $s = json_decode($this->GetBuffer('AvailabilityState'), true);
        if (!is_array($s)) $s = ['state' => 'UNKNOWN', 'checkedAt' => 0];
        $age = time() - (int)($s['checkedAt'] ?? 0);
        $s['stale'] = ($s['checkedAt'] ?? 0) === 0 || $age < 0 || $age > 90;
        $s['ready'] = !$s['stale'] && ($s['state'] ?? '') === 'READY'
            && $this->ReadPropertyBoolean('Enabled') && !IPS_HasChanges($this->InstanceID);
        $s['backend'] = $this->InstanceID;
        return json_encode($s, JSON_THROW_ON_ERROR);
    }

    public function CheckAvailability(): string
    {
        $lock = 'SECB.Availability.' . $this->InstanceID;
        if (!IPS_SemaphoreEnter($lock, 1)) return $this->GetAvailability();
        try {
            $s = json_decode($this->GetBuffer('AvailabilityState'), true) ?: [];
            $previous = $s['state'] ?? 'UNKNOWN';
            $s += ['recoveryAttempts' => 0, 'nextRecoveryAt' => 0, 'lastSuccessAt' => 0];
            $s['checkedAt'] = time();
            $s['state'] = 'UNAVAILABLE';
            $s['reason'] = '';
            if (!$this->ReadPropertyBoolean('Enabled')) $s['state'] = 'DISABLED';
            elseif (!$this->nativeInitialized()) $s['state'] = 'NOT_INITIALIZED';
            elseif (IPS_GetKernelRunlevel() !== 10103) $s['state'] = 'STARTING';
            elseif (IPS_HasChanges($this->InstanceID)) $s['reason'] = 'PENDING_SETTINGS';
            else {
                try {
                    $this->nativeApplication(); // Authenticity, active runtime and pinned foundation.
                    $s['state'] = 'READY';
                } catch (Throwable $e) {
                    // Only a fenced runtime is eligible for automatic activation. Integrity,
                    // missing storage, foundation drift and access errors never trigger it.
                    $pending = $e->getMessage() === 'Native runtime is fenced or recovery is pending.';
                    $s['reason'] = $pending ? 'RECOVERY_PENDING' : 'VALIDATION_FAILED';
                    if ($pending && $s['recoveryAttempts'] < 5 && time() >= $s['nextRecoveryAt']) {
                        ++$s['recoveryAttempts'];
                        $s['nextRecoveryAt'] = time() + min(300, 30 * (2 ** ($s['recoveryAttempts'] - 1)));
                        if ($this->Recover()) {
                            // Verify again; a successful return alone is not the health probe.
                            $this->nativeApplication();
                            $s['state'] = 'READY';
                        }
                    }
                }
            }
            if ($s['state'] === 'READY') {
                $s['lastSuccessAt'] = time(); $s['reason'] = '';
                $s['recoveryAttempts'] = 0; $s['nextRecoveryAt'] = 0;
                // Repair a disabled jobs timer without postponing a running one.
                if (function_exists('IPS_GetTimerList') && function_exists('IPS_GetTimer')) {
                    foreach (IPS_GetTimerList() as $id) {
                        $t = IPS_GetTimer($id);
                        if ((int)$t['InstanceID'] === $this->InstanceID && $t['Name'] === 'NativeJobs' && (int)$t['Interval'] === 0)
                            $this->SetTimerInterval('NativeJobs', 10000);
                    }
                }
            }
            $this->SetBuffer('AvailabilityState', json_encode($s, JSON_THROW_ON_ERROR));
            $health = $this->GetAvailability();
            $this->SetValue('Availability', $health);
            $this->SetValue('VaultError', !json_decode($health, true, 16, JSON_THROW_ON_ERROR)['ready']);
            if ($previous !== $s['state'] && function_exists('IPS_LogMessage'))
                IPS_LogMessage('SecretsBackend ' . $this->InstanceID, 'Availability: ' . $s['state'] . ($s['reason'] ? ' (' . $s['reason'] . ')' : ''));
            return $this->GetAvailability();
        } catch (Throwable $e) {
            $s = ['state'=>'UNAVAILABLE', 'reason'=>'HEALTH_CHECK_FAILED', 'checkedAt'=>time(),
                'recoveryAttempts'=>$s['recoveryAttempts']??0, 'nextRecoveryAt'=>$s['nextRecoveryAt']??0,
                'lastSuccessAt'=>$s['lastSuccessAt']??0];
            $this->SetBuffer('AvailabilityState', json_encode($s, JSON_THROW_ON_ERROR));
            $health = $this->GetAvailability();
            $this->SetValue('Availability', $health);
            $this->SetValue('VaultError', !json_decode($health, true, 16, JSON_THROW_ON_ERROR)['ready']);
            return $this->GetAvailability();
        } finally { IPS_SemaphoreLeave($lock); }
    }
}
