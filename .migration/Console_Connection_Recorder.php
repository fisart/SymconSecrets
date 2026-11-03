<?php
// Paste into a NEW, saved local Symcon PHP script and run once.
// Samples every 10 seconds for 10 minutes; run again to print the report.
// Creates only its own timer and a String variable below this script.
// No secret API calls, raw script text, configuration values or network requests.
$self = (int)($_IPS['SELF'] ?? 0);
if ($self <= 0 || !IPS_ScriptExists($self)) {
    echo "Save this as a local PHP script first.\n";
    return;
}
$lock = 'SecretsConsoleRecorder.' . $self;
if (!IPS_SemaphoreEnter($lock, 1)) return;
try {
    $reportID = 0;
    foreach (IPS_GetChildrenIDs($self) as $child) {
        if (IPS_GetObject($child)['ObjectIdent'] === 'ConsoleConnectionReport') $reportID = $child;
    }
    if (!$reportID) {
        $reportID = IPS_CreateVariable(3);
        IPS_SetParent($reportID, $self);
        IPS_SetIdent($reportID, 'ConsoleConnectionReport');
        IPS_SetName($reportID, 'Console connection report');
    }
    $report = json_decode(GetValueString($reportID), true);
    $timer = ($_IPS['SENDER'] ?? '') === 'TimerEvent';
    $now = time();
    if (is_array($report) && !$timer) {
        echo json_encode($report, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n";
        echo "Recording stops automatically at " . date('c', $report['stopAt']) . ". Clear the report variable to start a new recording.\n";
        return;
    }
    if (!is_array($report)) {
        if ($timer) { IPS_SetScriptTimer($self, 0); return; }
        $report = ['format'=>'SecretsConsoleRecorder.1', 'startedAt'=>$now,
            'stopAt'=>$now+600, 'status'=>'recording', 'samples'=>[]];
    }
    $tick = microtime(true);
    $sample = ['at'=>$now, 'kernelStart'=>IPS_GetKernelStartTime(), 'threads'=>0,
        'active'=>0, 'executions'=>0, 'workers'=>[], 'instances'=>[], 'timers'=>[]];
    $workers = [];
    foreach (IPS_GetScriptThreadList() as $id) {
        $thread = IPS_GetScriptThread($id);
        $sample['threads']++;
        $sample['executions'] += (int)$thread['ExecuteCount'];
        if ((int)$thread['StartTime'] <= 0 || $id === (int)($_IPS['THREAD'] ?? 0)) continue;
        $sample['active']++;
        // FilePath may contain inline PHP with credentials. Export only fixed labels.
        $operation = 'other';
        foreach (['SECB_RunNativeJobs','SECB_CallBoundLegacyAPI','SECB_CallLegacyAPI',
            'SEC_GetSecret','SEC_GetKeys','SEC_RetryNativeBinding','RS_FlushBuffer'] as $known) {
            if (str_contains((string)($thread['FilePath'] ?? ''), $known)) { $operation=$known; break; }
        }
        $workers[] = ['thread'=>(int)$id, 'senderID'=>(int)($thread['SenderID'] ?? 0),
            'seconds'=>max(0,$now-(int)$thread['StartTime']), 'operation'=>$operation,
            'averageMs'=>(int)$thread['ExecutionAvg'], 'maximumMs'=>(int)$thread['ExecutionMax']];
    }
    usort($workers, static fn($a,$b) => $b['seconds'] <=> $a['seconds']);
    $sample['workers'] = array_slice($workers, 0, 12);
    $ids = [];
    foreach (['{52165EDD-B2C0-40EC-8A59-42A97319B6E2}'=>'nativeBackend',
        '{7C5A3841-3F7B-4D2A-9E1C-5B6D8F9A0E12}'=>'secInterface',
        '{C6D3D6A3-0442-4217-9150-70588661C02D}'=>'remoteMirror'] as $module=>$role) {
        foreach (IPS_GetInstanceListByModuleID($module) as $id) {
            $ids[$id]=true;
            $sample['instances'][]=['id'=>$id,'role'=>$role,'status'=>IPS_GetInstance($id)['InstanceStatus']];
        }
    }
    foreach (IPS_GetTimerList() as $id) {
        if (!IPS_TimerExists($id)) continue;
        $t = IPS_GetTimer($id);
        if (!isset($ids[$t['InstanceID']])) continue;
        $sample['timers'][] = array_intersect_key($t,array_flip(['TimerID','InstanceID','Interval','LastRun','NextRun','Running']));
    }
    $last = end($report['samples']);
    $sample['sampleGapSeconds'] = $last ? $now-$last['at'] : 0;
    $sample['collectionMs'] = round((microtime(true)-$tick)*1000,1);
    $report['samples'][] = $sample;
    $report['samples'] = array_slice($report['samples'], -61);
    if ($now >= $report['stopAt'] || count($report['samples']) >= 61) {
        $report['status']='complete';
        IPS_SetScriptTimer($self, 0);
    }
    SetValueString($reportID, json_encode($report, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR));
    if (!$timer) {
        IPS_SetScriptTimer($self, 10);
        echo "Recording for 10 minutes. After reconnecting, run this script again to print the report. No instance IDs are needed.\n";
    }
} finally {
    IPS_SemaphoreLeave($lock);
}
