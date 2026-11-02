<?php
declare(strict_types=1);
require_once __DIR__ . '/NativePeer.php';
require_once __DIR__ . '/NativeBackup.php';
require_once __DIR__ . '/NativeHardware.php';
require_once __DIR__ . '/NativeEffects.php';
require_once __DIR__ . '/BackupOriginPolicy.php';
require_once __DIR__ . '/LegacyImport.php';

/** All web mutations below enter through the existing fresh, exact WebAuthn approval. */
final class SecretsBackendNativeOperations
{
    private string $session='';
    private ?array $legacyCommitSource=null;
    public function __construct(private SecretsBackendNativeStore $store,private SecretsBackendNativePeer $peer,private $hardwareApplied=null){}
    public function bindSession(string $hash): void { $this->session=$hash; }
    public static function actionClass(string $kind): string { return match($kind){'nativeBackup'=>'export','nativeReveal'=>'reveal','nativeRestore','nativeSharedSave','nativeSharedDelete'=>'write',default=>'identity'}; }
    public function uploads(): SecretsBackendNativeUploads { if($this->session==='')throw new RuntimeException('Administrator session required.');return new SecretsBackendNativeUploads($this->store,$this->session); }
    public static function machineTarget(array $state,string $scope): array
    {
        if(in_array($scope,['global','local'],true))return ['node'=>$state['vault'][$scope],'revision'=>$state['vault']['revision'],'treeId'=>$scope==='global'?$state['native']['globalTreeId']:$state['native']['vaultId'].':local','writable'=>$scope==='local'||$state['native']['globalWritable'],'kind'=>$scope];
        if(!preg_match('/^(owned|received):([a-f0-9-]{36})$/D',$scope,$m))throw new RuntimeException('Choose a current local, global or shared tree scope.');
        SecretsBackendNativePeer::uuid($m[2]);$kind=$m[1];$tree=$state['native'][$kind==='owned'?'trees':'received'][$m[2]]??null;
        if(!is_array($tree)||($kind==='received'&&isset($state['native']['trees'][$m[2]])))throw new RuntimeException('The selected shared tree is unavailable.');
        return ['node'=>$tree['node'],'revision'=>$tree['revision'],'treeId'=>$m[2],'writable'=>$kind==='owned'&&!$tree['frozen']&&$tree['owner']===$state['native']['vaultId'],'kind'=>$kind];
    }
    public function normalize(array $op,array $state,bool $stored): array
    {
        if($stored){$seal=$op['_nativeSeal']??'';unset($op['_nativeSeal']);if(!is_string($seal)||!hash_equals($this->store->opaque('native-operation:'.SecretsBackendNativeStore::canonical($op)),$seal))throw new RuntimeException('Native reviewed operation was changed.');$op['_nativeSeal']=$seal;return $op;}
        $kind=$op['kind']??'';
        if(in_array($kind,['nativeConnectStage','nativeConnectActivate','nativeConnectRevoke'],true)){
            $session=$this->store->get($this->session,'session');
            if($session['origin']!==$state['policy']['origin'])throw new RuntimeException('Approve backup access at the primary address.');
        }
        switch($kind){
            case 'nativeLegacyImport':
                SecretsBackendNativePeer::exact($op,['kind','candidate','digest']);$c=$this->legacyCandidate($op['candidate'],$op['digest'],$state);
                $fresh=SecretsBackendLegacyImport::read($c['source']['source']['id'],$this->legacyLimit());
                if(!hash_equals($fresh['fingerprint'],$c['source']['fingerprint']))throw new RuntimeException('The old vault or its settings changed. Review a new import.');
                $op['review']=$this->legacyReview($c,$state);$op['backupKey']=SecretsBackendCodec::b64(random_bytes(32));$op['backup']=SecretsBackendNativeBackup::encrypt($this->store,$op['backupKey'],$this->store->read());break;

            case 'nativeConnectStage':
                SecretsBackendNativePeer::exact($op,['kind','origin']);
                if(!is_string($op['origin']))throw new RuntimeException('Choose an exact Connect address.');
                $staged=SecretsBackendBackupOriginPolicy::stage($state,$op['origin']);$op['policy']=$staged['policy']['backupOrigin'];break;
            case 'nativeConnectRevoke':
                SecretsBackendNativePeer::exact($op,['kind','origin','generation']);SecretsBackendBackupOriginPolicy::revoke($state,$op['origin'],$op['generation']);break;
            case 'nativeConnectActivate':
                SecretsBackendNativePeer::exact($op,['kind','candidate','digest']);
                $c=$this->store->get($op['candidate'],'connect-candidate');
                if(!hash_equals(SecretsBootstrapVerifier::digest($c),$op['digest'])||!SecretsBackendCodec::same($c['head'],$this->store->head())||$c['expires']<time())throw new RuntimeException('Exact backup candidate changed or expired.');
                SecretsBackendBackupOriginPolicy::requireRoute($state,$c['origin'],$c['generation'],'register-options');
                if($state['policy']['backupOrigin']['status']!=='pending'||$c['entry']['administrator']!==$session['administrator']||$c['rights']!==['read','write','export'])throw new RuntimeException('Backup administrator authority differs.');
                $op['candidateRecord']=$c;break;
            case 'nativeInvite':SecretsBackendNativePeer::exact($op,['kind']);$op['invitation']=$this->peer->invitation();break;
            case 'nativePair':SecretsBackendNativePeer::exact($op,['kind','invitation','name']);$op=$this->peer->pairOperation($op['invitation'],$op['name']);break;
            case 'nativeAcceptPair':SecretsBackendNativePeer::exact($op,['kind','peerId']);$p=$state['pairing']['peers'][$op['peerId']]??null;if(!is_array($p)||$p['state']!=='PENDING_APPROVAL')throw new RuntimeException('Select the exact pending pairing request.');$op['pairDigest']=SecretsBackendNativePeer::digest($p['pair']);break;
            case 'nativeRevokePeer':SecretsBackendNativePeer::exact($op,['kind','peerId']);if(!isset($state['pairing']['peers'][$op['peerId']]))throw new RuntimeException('Unknown peer.');break;
            case 'nativeRotateKey':SecretsBackendNativePeer::exact($op,['kind']);$op['keyId']=SecretsBackendCodec::uuid();break;
            case 'nativeBackup':SecretsBackendNativePeer::exact($op,['kind']);$op['recoveryKey']=SecretsBackendCodec::b64(random_bytes(32));break;
            case 'nativeRestore':
                SecretsBackendNativePeer::exact($op,['kind','uploadId','recoveryKey','mode']);if(!in_array($op['mode'],['replace-values','local-copy'],true))throw new RuntimeException('Choose the reviewed recovery mode.');
                $bytes=$this->uploads()->read($op['uploadId']);$backup=SecretsBackendNativeBackup::decrypt($bytes,$op['recoveryKey'],$this->store->metadata()['capacityBytes']);
                $op['backupDigest']=hash('sha256',$bytes);$op['sourceVault']=$backup['identity']['deploymentId'];$op['sourceAt']=$backup['at'];break;
            case 'nativeMachineGrant':
                SecretsBackendNativePeer::exact($op,['kind','name','scope','path','write']);SecretsBackendNativePeer::name($op['name']);
                if(!is_string($op['scope'])||!is_array($op['path'])||!is_bool($op['write']))throw new RuntimeException('Choose an exact machine scope, path and write permission.');SecretsBackendTree::path($op['path']);
                $target=self::machineTarget($state,$op['scope']);if($op['write']&&!$target['writable'])throw new RuntimeException('Received or frozen shared trees permit read-only machine access.');
                SecretsBackendTree::at($target['node'],$op['path']);$op['treeId']=$target['treeId'];$op['id']=SecretsBackendCodec::uuid();$op['token']=SecretsBackendCodec::b64(random_bytes(32));break;
            case 'nativeMachineRevoke':SecretsBackendNativePeer::exact($op,['kind','id']);if(!isset($state['native']['machines'][$op['id']]))throw new RuntimeException('Unknown machine capability.');break;
            case 'nativeCompact':SecretsBackendNativePeer::exact($op,['kind','uploadId','recoveryKey']);$bytes=$this->uploads()->read($op['uploadId']);$material=SecretsBackendNativeBackup::decrypt($bytes,$op['recoveryKey'],$this->store->metadata()['capacityBytes']);$this->store->verifyOwnBackup($material,$state);$op['backupDigest']=hash('sha256',$bytes);break;
            case 'nativeReveal':
                SecretsBackendNativePeer::exact($op,['kind','treeId','path','revision']);$r=$state['native']['trees'][$op['treeId']]??$state['native']['received'][$op['treeId']]??null;
                if(!is_array($r)||$r['revision']!==$op['revision']||!is_array($op['path']))throw new RuntimeException('Received record changed.');
                SecretsBackendTree::path($op['path']);SecretsBackendTree::at($r['node'],$op['path']);break;
            case 'nativeResync':
                SecretsBackendNativePeer::exact($op,['kind','peerId']);$p=$state['pairing']['peers'][$op['peerId']]??null;if(!is_array($p)||!$p['active'])throw new RuntimeException('Pair this recipient first.');
                $op['cursor']=$this->peer->exchange($p,'STATUS',['treeId'=>$state['native']['globalTreeId']],SecretsBackendCodec::uuid());break;
            case 'nativeHardwareProfile':
                SecretsBackendNativePeer::exact($op,['kind','roots','aaguids','allowReenrollmentLock']);if(!is_array($op['roots'])||!is_array($op['aaguids'])||!is_bool($op['allowReenrollmentLock']))throw new RuntimeException('Invalid hardware trust review.');
                if(in_array(true,$state['policy']['hardware'],true)&&!$op['allowReenrollmentLock'])throw new RuntimeException('Confirm the hardware re-enrollment requirement before changing an enforced trust profile.');
                $profile=SecretsBackendNativeHardware::normalize($op['roots'],$op['aaguids']);$op['certificates']=$profile['roots'];$op['hashes']=$profile['hashes'];$op['aaguids']=$profile['aaguids'];$op['version']=$profile['version'];unset($op['roots']);break;
            case 'nativeEnrollment':
                SecretsBackendNativePeer::exact($op,['kind','candidate','digest']);
                $candidate=$this->store->get($op['candidate'],'key-candidate');
                if($candidate['session']!==$this->session||!hash_equals(SecretsBootstrapVerifier::digest($candidate),$op['digest'])||!SecretsBackendCodec::same($candidate['head'],$this->store->head()))throw new RuntimeException('The exact key candidate changed or expired.');
                $op['entry']=$candidate['entry'];$op['expires']=time()+90;break;
            case 'nativeProvider':$op=SecretsBackendNativeEffects::configure($op,$state);break;
            case 'nativeProviderDisable':SecretsBackendNativePeer::exact($op,['kind','id']);if(!isset($state['native']['providers'][$op['id']]))throw new RuntimeException('Unknown provider.');break;
            case 'nativeRefresh':SecretsBackendNativePeer::exact($op,['kind','id']);$op['effect']=(new SecretsBackendNativeEffects($this->store))->prepare($state,$op['id']);break;
            case 'nativeEffectApply':case 'nativeEffectAbandon':
                SecretsBackendNativePeer::exact($op,['kind','id']);if(!preg_match('/^[a-f0-9]{64}$/D',$op['id'])||!isset($state['native']['effects'][$op['id']]))throw new RuntimeException('Unknown provider effect.');
                if($kind==='nativeEffectApply'&&$this->store->readCapturedEffect($op['id'],$state['native']['effects'][$op['id']]['requestDigest'])===null)throw new RuntimeException('No authenticated captured response exists; do not resend an uncertain request.');break;
            case 'nativeTransferOffer':SecretsBackendNativePeer::exact($op,['kind','treeId','peerId']);$op=$this->peer->ownerOffer($state,$op['treeId'],$op['peerId']);break;
            case 'nativeTransferAccept':
                SecretsBackendNativePeer::exact($op,['kind','transferId']);$t=$state['native']['transfers'][$op['transferId']]??null;
                if(!is_array($t)||$t['direction']!=='incoming'||$t['state']!=='PENDING_APPROVAL')throw new RuntimeException('Select a pending transfer offered to this vault.');
                $op['certificateDigest']=SecretsBackendNativePeer::digest($t['certificate']);$op['acceptance']=$this->peer->acceptance($t['certificate']);break;
            case 'nativeSharedSave':case 'nativeSharedDelete':
                SecretsBackendNativePeer::exact($op,$kind==='nativeSharedSave'?['kind','treeId','path','revision','mode','json']:['kind','treeId','path','revision']);
                $tree=$state['native']['trees'][$op['treeId']]??null;
                if(!is_array($tree)||$tree['owner']!==$state['native']['vaultId']||$tree['frozen']||$tree['revision']!==$op['revision']||!is_array($op['path'])||!$op['path'])throw new RuntimeException('This tree is frozen, stale or owned by another vault.');
                SecretsBackendTree::path($op['path']);if($kind==='nativeSharedSave'){if(!in_array($op['mode'],['create','replace'],true)||!is_string($op['json']))throw new RuntimeException('Invalid owned-tree edit.');SecretsBackendTree::parse($op['json']);}else SecretsBackendTree::at($tree['node'],$op['path']);break;
            case 'nativeFork':SecretsBackendNativePeer::exact($op,['kind','treeId']);if($op['treeId']!==$state['native']['globalTreeId']||$state['native']['globalWritable'])throw new RuntimeException('Fork only the selected frozen global lineage.');$op['newTreeId']=SecretsBackendCodec::uuid();break;
            default:throw new RuntimeException('Unknown native management operation.');
        }
        $op['_nativeSeal']=$this->store->opaque('native-operation:'.SecretsBackendNativeStore::canonical($op));return $op;
    }
    public function apply(array $op,array $s): array
    {
        $kind=$op['kind'];
        if($kind==='nativeLegacyImport'){
            $c=$this->legacyCandidate($op['candidate'],$op['digest'],$s);
            if($this->legacyCommitSource===null||!hash_equals($this->legacyCommitSource['fingerprint'],$c['source']['fingerprint']))throw new RuntimeException('Import source is not locked and verified.');
            $plan=SecretsBackendLegacyImport::plan($s,$c['source'],$c['policy'],$this->legacyLimit());
            $changed=false;foreach(['global','local']as$scope){
                if(SecretsBackendNativeStore::canonical($s['vault'][$scope])!==SecretsBackendNativeStore::canonical($plan['trees'][$scope])){
                    if($scope==='global'&&!$s['native']['globalWritable'])throw new RuntimeException('This vault does not own the global tree. Import into its owner.');
                    $s['vault'][$scope]=$plan['trees'][$scope];$changed=true;
                    if($scope==='global'){$s['stream']['globalRevision']=SecretsBackendCodec::increment($s['stream']['globalRevision']);$s=SecretsBackendNativePeer::queueGlobal($s);}
                }
                if(SecretsBackendNativeStore::canonical($s['vault'][$scope])!==SecretsBackendNativeStore::canonical($plan['trees'][$scope]))throw new RuntimeException('Imported tree verification failed.');
            }
            if($changed)$s['vault']['revision']=SecretsBackendCodec::increment($s['vault']['revision']);
            $storage=$c['storage'];$settings=&$s['policy']['management']['settings'];
            $checked=$this->store->reviewStorageMove($storage['to'],IPS_GetKernelDir(),$storage['legacyParent']);
            if($checked['from']!==$storage['from']||$checked['to']!==$storage['to'])throw new RuntimeException('Storage locations changed after review.');
            if($storage['from']!==$storage['to']){
                $s['native']['storageMove']=$storage;
                $settings['DataDirectory']=$storage['to']['vaultDirectory'];$settings['KeyDirectory']=$storage['to']['keyDirectory'];
                $roots=$settings['HardwareRootsDirectory'];
                if($roots!==''&&SecretsBackendNativePlatform::contains($storage['from']['keyDirectory'],$roots))$settings['HardwareRootsDirectory']=$storage['to']['keyDirectory'].substr($roots,strlen($storage['from']['keyDirectory']));
                $s['policy']['version']=SecretsBackendCodec::increment($s['policy']['version']);
            }
            unset($settings);
            $source=$c['source']['source'];$s['native']['legacyImports'][(string)$source['id']]=['source'=>$source,'summary'=>$plan['summary'],'at'=>gmdate('c'),'revision'=>$s['vault']['revision'],'excluded'=>$c['source']['excluded'],'storageAction'=>$storage['from']===$storage['to']?'keep-current':'use-selected','storage'=>$storage['to'],'connectionsActive'=>false];
        }elseif($kind==='nativeConnectStage'){
            SecretsBackendBackupOriginPolicy::stage($s,$op['origin']);$s['policy']['backupOrigin']=$op['policy'];
        }elseif($kind==='nativeConnectRevoke'){
            $s=SecretsBackendBackupOriginPolicy::revoke($s,$op['origin'],$op['generation']);
        }elseif($kind==='nativeConnectActivate'){
            $c=$this->store->get($op['candidate'],'connect-candidate');
            if($c['expires']<time()||!hash_equals(SecretsBootstrapVerifier::digest($c),$op['digest'])||SecretsBootstrapVerifier::digest($c)!==SecretsBootstrapVerifier::digest($op['candidateRecord']))throw new RuntimeException('Backup candidate expired or changed.');
            SecretsBackendBackupOriginPolicy::requireRoute($s,$c['origin'],$c['generation'],'register-options');
            if($s['policy']['backupOrigin']['status']!=='pending'||isset($s['identity']['credentials'][$c['entry']['id']])||$c['entry']['administrator']!==$s['identity']['ownerId']||$c['rights']!==['read','write','export']||!$c['entry']['tested'])throw new RuntimeException('Backup authority changed.');
            if(in_array(true,$s['policy']['hardware'],true)&&(!$c['entry']['hardware']||$c['entry']['trustVersion']!==$s['policy']['management']['settings']['HardwareTrustVersion']))throw new RuntimeException('Current hardware policy requires a verified backup key.');
            $s['identity']['credentials'][$c['entry']['id']]=$c['entry'];$s['policy']['backupOrigin']['status']='active';
        }elseif($kind==='nativeEnrollment'){
            $candidate=$this->store->get($op['candidate'],'key-candidate');
            if($op['expires']<time()||$candidate['session']!==$this->session||!hash_equals(SecretsBootstrapVerifier::digest($candidate),$op['digest'])||isset($s['identity']['credentials'][$op['entry']['id']]))throw new RuntimeException('The reviewed key candidate expired, changed or already exists.');
            $s['identity']['credentials'][$op['entry']['id']]=$op['entry'];$s['identity']['revocation']=SecretsBackendCodec::increment($s['identity']['revocation']);
        }elseif($kind==='nativeInvite'){
            foreach($s['native']['invites']as$id=>$i)if((int)$i['expires']<time())unset($s['native']['invites'][$id]);
            if(count($s['native']['invites'])>=16)throw new RuntimeException('Too many pending invitations.');
            $i=$op['invitation'];if((int)$i['expires']<time())throw new RuntimeException('Invitation expired during approval.');$s['native']['invites'][$i['id']]=$i+['usedBy'=>null];
        }elseif($kind==='nativePair'){
            $pair=$op['pair'];SecretsBackendNativePeer::pairCheck($pair);$remote=$pair['a'];
            if((int)$op['expires']<time()||(isset($s['pairing']['peers'][$remote['vaultId']])&&$s['pairing']['peers'][$remote['vaultId']]['state']!=='REVOKED')||count($s['pairing']['peers'])>=32)throw new RuntimeException('Pairing expired, already exists or exceeds capacity.');
            $row=SecretsBackendNativePeer::peerRecord($pair,$remote,$op['name'],'PENDING_REMOTE');$row+=['requestId'=>$op['requestId'],'expires'=>$op['expires']];$s['pairing']['peers'][$row['id']]=$row;
            $s['outbox']['jobs'][]=SecretsBackendNativePeer::job($row,'PAIR_REQUEST',['invitationId'=>$op['invitationId'],'expires'=>$op['expires'],'pair'=>$pair,'proof'=>$op['proof']],'0',$op['requestId']);
        }elseif($kind==='nativeAcceptPair'){
            $p=$s['pairing']['peers'][$op['peerId']]??null;if(!is_array($p)||$p['state']!=='PENDING_APPROVAL'||(int)$p['expires']<time()||SecretsBackendNativePeer::digest($p['pair'])!==$op['pairDigest'])throw new RuntimeException('The pending peer approval changed or expired.');
            $s['pairing']['peers'][$p['id']]['active']=true;$s['pairing']['peers'][$p['id']]['state']='ACTIVE';$p['active']=true;
            $s['outbox']['jobs'][]=SecretsBackendNativePeer::job($p,'PAIR_ACCEPT',['pairDigest'=>$op['pairDigest'],'requestId'=>$p['requestId']]);$s=SecretsBackendNativePeer::queueGlobal($s,$p['id']);
        }elseif($kind==='nativeRevokePeer'){
            $p=$s['pairing']['peers'][$op['peerId']];$s=SecretsBackendNativePeer::revoke($s,$p['id']);$s['outbox']['jobs'][]=SecretsBackendNativePeer::job($p,'REVOKE',['reason'=>'administrator-revoked']);
        }elseif($kind==='nativeRotateKey'){$this->store->prepareDataKey($op['keyId']);$s['native']['activeDataKeyId']=$op['keyId'];
        }elseif($kind==='nativeMachineGrant'){
            if(count($s['native']['machines'])>=128)throw new RuntimeException('Machine capability capacity reached.');
            $target=self::machineTarget($s,$op['scope']);if($target['treeId']!==$op['treeId']||($op['write']&&!$target['writable']))throw new RuntimeException('Machine grant target changed.');
            $s['native']['machines'][$op['id']]=['id'=>$op['id'],'name'=>$op['name'],'hash'=>hash('sha256',$op['token']),'scope'=>$op['scope'],'treeId'=>$op['treeId'],'path'=>$op['path'],'write'=>$op['write'],'active'=>true,'sequence'=>'0'];
        }elseif($kind==='nativeMachineRevoke'){$s['native']['machines'][$op['id']]['active']=false;
        }elseif($kind==='nativeRestore'){
            $bytes=$this->uploads()->read($op['uploadId']);if(!hash_equals($op['backupDigest'],hash('sha256',$bytes)))throw new RuntimeException('The reviewed backup changed.');
            $backup=SecretsBackendNativeBackup::decrypt($bytes,$op['recoveryKey'],$this->store->metadata()['capacityBytes']);
            if($op['mode']==='replace-values'){
                if(!$s['native']['globalWritable'])throw new RuntimeException('A transferred/frozen global tree cannot be replaced. Choose local-copy recovery.');
                $s['vault']['global']=$backup['state']['vault']['global'];$s['vault']['local']=$backup['state']['vault']['local'];
                $s['stream']['globalRevision']=SecretsBackendCodec::increment($s['stream']['globalRevision']);$s=SecretsBackendNativePeer::queueGlobal($s);
            }else{
                $node=['type'=>'object','entries'=>[['key'=>'global','node'=>$backup['state']['vault']['global']],['key'=>'local','node'=>$backup['state']['vault']['local']]]];
                SecretsBackendTree::edit($s['vault']['local'],['Recovered-'.$op['sourceVault']],$node,'create');
            }
            $s['vault']['revision']=SecretsBackendCodec::increment($s['vault']['revision']);
            $s['native']['recoveryRecords'][]=['source'=>$op['sourceVault'],'digest'=>$op['backupDigest'],'at'=>gmdate('c'),'mode'=>$op['mode']];
            // Current credentials, rights, peers and uncertain effects remain authoritative.
        }elseif($kind==='nativeHardwareProfile'){
            if(in_array(true,$s['policy']['hardware'],true)&&!$op['allowReenrollmentLock'])throw new RuntimeException('Hardware re-enrollment was not acknowledged.');
            $path=$this->store->installHardwareRoots($op['version'],$op['certificates']);$profile=$s['policy']['management'];
            $profile['settings']['HardwareRootsDirectory']=$path;$profile['settings']['HardwareAAGUIDs']=SecretsBackendCodec::json($op['aaguids']);$profile['settings']['HardwareTrustVersion']=$op['version'];$profile['files']=['HardwareRoots'=>$op['hashes']];
            $s['policy']['management']=$profile;$s['policy']['version']=SecretsBackendCodec::increment($s['policy']['version']);
        }elseif($kind==='nativeProvider'){
            if(count($s['native']['providers'])>=32&&!isset($s['native']['providers'][$op['id']]))throw new RuntimeException('Provider capacity reached.');$old=$s['native']['providers'][$op['id']]??null;$p=$op;unset($p['kind'],$p['_nativeSeal']);
            $s['native']['providers'][$op['id']]=$p+['active'=>true,'activeEffect'=>$old['activeEffect']??null,'status'=>($old['activeEffect']??null)!==null?'QUARANTINED':'READY','nextAt'=>0,'refreshGeneration'=>$old['refreshGeneration']??'0'];
        }elseif($kind==='nativeProviderDisable'){$s['native']['providers'][$op['id']]['active']=false;$s['native']['providers'][$op['id']]['automatic']=false;
        }elseif($kind==='nativeRefresh'){$s=SecretsBackendNativeEffects::add($s,$op['effect']);
        }elseif($kind==='nativeEffectAbandon'){
            $e=$s['native']['effects'][$op['id']];if(in_array($e['state'],['COMPLETE','ERROR'],true))throw new RuntimeException('Effect already has a terminal response.');$s['native']['effects'][$op['id']]['state']='ABANDONED';$p=$e['providerId'];$s['native']['providers'][$p]['activeEffect']=null;$s['native']['providers'][$p]['automatic']=false;$s['native']['providers'][$p]['status']='REAUTHORIZE_REQUIRED';
            // Keep the external predecessor tombstone: abandonment is not permission to resend.
        }elseif($kind==='nativeTransferOffer'){
            $cert=$op['certificate'];$isGlobal=$op['treeId']===$s['native']['globalTreeId'];
            if($isGlobal){if(!$s['native']['globalWritable']||$cert['revision']!==$s['stream']['globalRevision']||SecretsBackendNativePeer::digest($s['vault']['global'])!==$cert['nodeDigest'])throw new RuntimeException('Owner transfer state changed.');$s['native']['globalWritable']=false;}
            else{if(!isset($s['native']['trees'][$op['treeId']])||$s['native']['trees'][$op['treeId']]['frozen'])throw new RuntimeException('Tree is not available for transfer.');$s['native']['trees'][$op['treeId']]['frozen']=true;}
            $s['native']['transfers'][$cert['id']]=['direction'=>'outgoing','state'=>'FROZEN','certificate'=>$cert,'peerId'=>$op['peerId']];
            $s['outbox']['jobs']=array_values(array_filter($s['outbox']['jobs'],static fn($j)=>!(($j['kind']==='SYNC'&&($j['payload']['treeId']??'')===$op['treeId'])||($j['kind']==='TREE_SYNC'&&($j['treeId']??'')===$op['treeId']))));
            $target=$s['pairing']['peers'][$op['peerId']];$s['outbox']['jobs'][]=SecretsBackendNativePeer::job($target,'OWNER_OFFER',['certificate'=>$cert,'node'=>$op['node']]);
        }elseif($kind==='nativeTransferAccept'){
            $t=$s['native']['transfers'][$op['transferId']]??null;if(!is_array($t)||$t['direction']!=='incoming'||$t['state']!=='PENDING_APPROVAL'||SecretsBackendNativePeer::digest($t['certificate'])!==$op['certificateDigest'])throw new RuntimeException('Transfer offer changed.');
            $cert=$t['certificate'];if(SecretsBackendNativePeer::authority($cert['newOwner'])!==SecretsBackendNativePeer::authority($this->peer->descriptor()))throw new RuntimeException('Wrong new owner.');
            $subscribers=[];foreach($cert['recipients']as$r)$subscribers[$r['recipient']['vaultId']]=['descriptor'=>$r['recipient'],'subscriptionId'=>$r['subscriptionId'],'sequence'=>'0','nodeDigest'=>$cert['nodeDigest']];
            $s['native']['trees'][$cert['treeId']]=['owner'=>$s['native']['vaultId'],'epoch'=>$cert['newEpoch'],'revision'=>$cert['revision'],'node'=>$t['node'],'frozen'=>false,'certificate'=>$cert,'acceptance'=>$op['acceptance'],'subscribers'=>$subscribers];
            $s['native']['transfers'][$op['transferId']]['state']='ACCEPTED';$s['vault']['revision']=SecretsBackendCodec::increment($s['vault']['revision']);$s=SecretsBackendNativePeer::queueOwned($s,$cert['treeId']);
        }elseif(in_array($kind,['nativeSharedSave','nativeSharedDelete'],true)){
            $tree=$s['native']['trees'][$op['treeId']]??null;if(!is_array($tree)||$tree['frozen']||$tree['owner']!==$s['native']['vaultId']||$tree['revision']!==$op['revision'])throw new RuntimeException('Owned tree changed before commit.');
            SecretsBackendTree::edit($s['native']['trees'][$op['treeId']]['node'],$op['path'],$kind==='nativeSharedSave'?SecretsBackendTree::parse($op['json']):null,$kind==='nativeSharedSave'?$op['mode']:'delete');
            $s['native']['trees'][$op['treeId']]['revision']=SecretsBackendCodec::increment($tree['revision']);$s['vault']['revision']=SecretsBackendCodec::increment($s['vault']['revision']);$s=SecretsBackendNativePeer::queueOwned($s,$op['treeId']);
        }elseif($kind==='nativeFork'){
            if($s['native']['globalTreeId']!==$op['treeId']||$s['native']['globalWritable'])throw new RuntimeException('Frozen lineage changed.');
            $s['native']['globalTreeId']=$op['newTreeId'];$s['native']['ownershipEpoch']='1';$s['native']['globalWritable']=true;$s['stream']['globalRevision']='0';$s['stream']['next']=[];$s['stream']['queuedDigest']=[];
            foreach($s['native']['machines']as&$grant)if($grant['scope']==='global')$grant['active']=false;unset($grant);
            foreach($s['pairing']['peers']as&$p){$p['active']=false;$p['state']='REVOKED';}unset($p);$s['outbox']['jobs']=[];
            $s['native']['recoveryRecords'][]=['sourceTree'=>$op['treeId'],'newTree'=>$op['newTreeId'],'mode'=>'explicit-unfenced-fork','at'=>gmdate('c')];
        }elseif($kind==='nativeResync'){
            $cursor=$op['cursor'];$p=$s['pairing']['peers'][$op['peerId']];
            if(!$p['active']||($cursor['status']??'')!=='CURSOR'||SecretsBackendNativePeer::compare($cursor['revision'],$s['stream']['globalRevision'])>0)throw new RuntimeException('The remote copy is newer; reconcile the restored owner instead of overwriting it.');
            $seq=SecretsBackendCodec::increment($s['stream']['next'][$p['id']]??'0');if(SecretsBackendNativePeer::compare($seq,$cursor['sequence'])<=0)$seq=SecretsBackendCodec::increment($cursor['sequence']);
            $s['outbox']['jobs']=array_values(array_filter($s['outbox']['jobs'],static fn($j)=>$j['receiverId']!==$p['id']||!in_array($j['kind'],['SYNC','RESYNC'],true)));
            $node=$s['vault']['global'];$digest=SecretsBackendNativePeer::digest($node);$s['stream']['next'][$p['id']]=$seq;$s['stream']['queuedDigest'][$p['id']]=$digest;
            $payload=['treeId'=>$s['native']['globalTreeId'],'owner'=>$s['native']['vaultId'],'ownershipEpoch'=>$s['native']['ownershipEpoch'],'revision'=>$s['stream']['globalRevision'],'previousDigest'=>$cursor['nodeDigest'],'nodeDigest'=>$digest,'node'=>$node,'challenge'=>$cursor['challenge']];
            $s['outbox']['jobs'][]=SecretsBackendNativePeer::job($p,'RESYNC',$payload,$seq);
        }
        return $s;
    }
    public function result(array $op,array $validated): array
    {
        return match($op['kind']){
            'nativeLegacyImport'=>$this->legacyResult($op,$validated),
            'nativeInvite'=>['invitation'=>SecretsBackendNativePeer::invitationText($op['invitation']),'clearAfterSeconds'=>60],
            'nativeMachineGrant'=>['machineId'=>$op['id'],'capabilityToken'=>$op['token'],'clearAfterSeconds'=>60],
            'nativeBackup'=>['backup'=>SecretsBackendNativeBackup::encrypt($this->store,$op['recoveryKey'],$validated),'recoveryKey'=>$op['recoveryKey'],'clearAfterSeconds'=>60],
            'nativeRestore'=>$this->restoreResult($op),
            'nativeCompact'=>$this->compactResult($op),
            'nativeHardwareProfile'=>$this->hardwareResult($validated['state']['policy']['management']),
            'nativeEffectApply'=>$this->effectResult($op),
            'nativeReveal'=>['fields'=>SecretsBackendTree::reveal(SecretsBackendTree::at(($validated['state']['native']['trees'][$op['treeId']]['node']??$validated['state']['native']['received'][$op['treeId']]['node']),$op['path'])),'clearAfterSeconds'=>30],
            default=>['nativeChanged'=>true]
        };
    }
    private function restoreResult(array $op): array { try{$this->uploads()->remove($op['uploadId']);}catch(Throwable $ignored){}return ['restored'=>true,'authorityRestored'=>false]; }
    private function compactResult(array $op): array { $this->store->compactOutcomes();$this->store->compactKeys();try{$this->uploads()->remove($op['uploadId']);}catch(Throwable $ignored){}return ['compacted'=>true,'retainedOutcomes'=>512,'oldUnknownOperations'=>'do-not-replay']; }
    private function effectResult(array $op): array { $effect=$this->store->read()['state']['native']['effects'][$op['id']];$capture=$this->store->readCapturedEffect($effect['id'],$effect['requestDigest']);return (new SecretsBackendNativeEffects($this->store))->complete($effect,$capture); }
    private function hardwareResult(array $profile): array { if($this->hardwareApplied!==null)($this->hardwareApplied)($profile);return ['hardwareProfileApplied'=>true,'reloginRequired'=>true]; }
    public function request(string $action,array $data): array
    {
        if($action==='legacySources'){SecretsBackendNativePeer::exact($data,[]);return ['sources'=>SecretsBackendLegacyImport::sources()];}
        if($action==='legacyPreview')return $this->legacyPreview($data);
        if($action==='nativeUploadBegin'){SecretsBackendNativePeer::exact($data,['length','digest']);if(!is_int($data['length'])||!is_string($data['digest']))throw new RuntimeException('Invalid upload metadata.');return $this->uploads()->begin($data['length'],$data['digest']);}
        if($action==='nativeUploadChunk'){SecretsBackendNativePeer::exact($data,['uploadId','index','chunk']);if(!is_string($data['uploadId'])||!is_int($data['index'])||!is_string($data['chunk']))throw new RuntimeException('Invalid upload chunk.');return $this->uploads()->chunk($data['uploadId'],$data['index'],$data['chunk']);}
        if($action==='nativeUploadFinish'){SecretsBackendNativePeer::exact($data,['uploadId']);return $this->uploads()->finish($data['uploadId']);}
        if($action==='nativeOperationStatus'){SecretsBackendNativePeer::exact($data,['operationId']);SecretsBackendNativePeer::uuid($data['operationId']);return $this->store->operationStatus($data['operationId']);}
        throw new RuntimeException('Unsupported native request.');
    }
    public function summary(array $op): array
    {
        $out=['kind'=>$op['kind']];
        if($op['kind']==='nativeLegacyImport')$out+=$op['review'];
        if($op['kind']==='nativeConnectStage')$out+=['origin'=>$op['origin'],'effect'=>'Allow restricted backup passkey enrollment only; no general access yet.'];
        if($op['kind']==='nativeConnectRevoke')$out+=['origin'=>$op['origin'],'generation'=>$op['generation'],'effect'=>'Invalidate backup sessions, challenges and pending enrollment.'];
        if($op['kind']==='nativeConnectActivate'){$c=$op['candidateRecord'];$out+=['origin'=>$c['origin'],'rpId'=>parse_url($c['origin'],PHP_URL_HOST),'administrator'=>$c['entry']['administrator'],'userHandle'=>$c['entry']['userHandle'],'credential'=>$c['entry']['id'],'fingerprint'=>hash('sha256',$c['entry']['publicKey']),'browserKey'=>$c['keyDigest'],'rights'=>$c['rights'],'candidateDigest'=>$op['digest'],'effect'=>'Activate exactly this tested backup credential.'];}

        foreach(['label','hardware','probe','name','scope','path','write','peerId','mode','sourceVault','sourceAt','backupDigest','treeId','transferId','newTreeId']as$key)if(isset($op[$key]))$out[$key]=$op[$key];
        if(isset($op['pair']))$out+=['peerURL'=>$op['pair']['a']['endpoint'],'peerVault'=>$op['pair']['a']['vaultId'],'peerFingerprint'=>hash('sha256',$op['pair']['a']['signKey']),'pairingDigest'=>SecretsBackendNativePeer::digest($op['pair'])];
        if($op['kind']==='nativeHardwareProfile')$out+=['trustVersion'=>$op['version'],'certificateFingerprints'=>$op['hashes'],'allowedAAGUIDs'=>$op['aaguids'],'effect'=>'Existing verified hardware credentials must be re-enrolled and tested against this new trust generation. Hardware-only policy remains enforced.'];
        if(isset($op['certificate']))$out+=['ownershipCertificate'=>SecretsBackendNativePeer::digest($op['certificate']),'newOwner'=>$op['certificate']['newOwner'],'recipients'=>count($op['certificate']['recipients']),'effect'=>'Freeze this writer permanently within the current lineage; the new owner must explicitly accept.'];
        if($op['kind']==='nativeFork')$out['effect']='Create a new global tree identity. This does not fence the old owner. Existing global machine grants and ordinary pairings are revoked; re-pair selected recipients explicitly.';
        if($op['kind']==='nativeRestore')$out['authority']='Keep current credentials, permissions, peer identities and uncertain external effects; restore reviewed values only.';
        if($op['kind']==='nativeProvider')$out+=array_intersect_key($op,array_flip(['endpoint','clientId','authentication','secretScope','secretPath','refreshScope','refreshPath','resultScope','resultPath','accessField','automatic','idempotencySupported','idempotencyHeader']));
        if($op['kind']==='nativeRefresh')$out['effect']='Authorize this exact token-refresh predecessor once. An uncertain non-idempotent response is quarantined and never resent automatically.';
        if($op['kind']==='nativeEffectAbandon')$out['effect']='Keep the uncertainty tombstone, disable automatic refresh and require a newly authorized refresh token. No request is repeated.';
        if($op['kind']==='nativeCompact')$out['retention']='Keep the latest 512 mutation outcomes/audit entries. Old unknown operations must never be replayed automatically. Pending jobs, effects and receiver cursors are kept.';
        return $out;
    }
    private function legacyLimit(): int { return min(524288,(int)$this->store->metadata()['capacityBytes']); }
    private function legacyCandidate(string $id,string $digest,array $state): array
    {
        $c=$this->store->get($id,'legacy-import');
        if($c['session']!==$this->session||$c['expires']<time()||!hash_equals($this->store->opaque('legacy-import:'.SecretsBackendNativeStore::canonical($c)),$digest)||!SecretsBackendCodec::same($c['head'],$this->store->head()))throw new RuntimeException('Import review expired or the destination changed. Review again.');
        return $c;
    }
    private function legacyReview(array $c,array $state): array
    {
        $plan=SecretsBackendLegacyImport::plan($state,$c['source'],$c['policy'],$this->legacyLimit());
        if(!$state['native']['globalWritable']&&SecretsBackendNativeStore::canonical($plan['trees']['global'])!==SecretsBackendNativeStore::canonical($state['vault']['global']))throw new RuntimeException('Import global secrets at the vault that owns this tree.');
        return ['source'=>$c['source']['source'],'excluded'=>$c['source']['excluded'],'summary'=>$plan['summary'],'conflictPolicy'=>$c['policy'],
            'storage'=>['action'=>$c['storage']['from']===$c['storage']['to']?'keep-current':'use-selected','choices'=>$c['storage']['choices'],'current'=>$c['storage']['from']]+$c['storage']['to'],
            'activeRecipients'=>count(array_filter($state['pairing']['peers'],static fn($peer)=>$peer['active'])),'connections'=>'Imported as inactive proposals; new pairing is required. Global imports follow existing active new-vault sharing.','authority'=>'Retain current administrators, keys, grants and peer trust.'];
    }
    private function legacyPreview(array $data): array
    {
        $data+=['vaultLocation'=>'current','keyLocation'=>'current','privateACLConfirmed'=>false,'persistenceConfirmed'=>false];
        SecretsBackendNativePeer::exact($data,['source','policy','vaultLocation','keyLocation','privateACLConfirmed','persistenceConfirmed']);if(!is_int($data['source'])||!is_string($data['policy']))throw new RuntimeException('Select the old vault and conflict policy.');
        $current=$this->store->read();$source=SecretsBackendLegacyImport::read($data['source'],$this->legacyLimit());
        $plan=SecretsBackendLegacyImport::plan($current['state'],$source,$data['policy'],$this->legacyLimit());
        foreach(['vaultLocation','keyLocation'] as $choice)if(!in_array($data[$choice],['current','imported'],true))throw new RuntimeException('Choose current or imported locations.');
        foreach(['privateACLConfirmed','persistenceConfirmed'] as $confirmation)if(!is_bool($data[$confirmation]))throw new RuntimeException('Invalid storage confirmation.');
        if(IPS_HasChanges((int)$this->store->identity()['binding']['backend']))throw new RuntimeException('Apply or discard pending backend console edits before importing.');
        $from=$this->store->storagePaths();$target=['vaultDirectory'=>$data['vaultLocation']==='current'?$from['vaultDirectory']:$source['source']['suggestedVaultDirectory'],'keyDirectory'=>$data['keyLocation']==='current'?$from['keyDirectory']:$source['source']['suggestedKeyDirectory']];
        $parents=$current['state']['native']['storageMove']['legacyParent']??null;
        if(!is_array($parents))$parents=['vaultDirectory'=>$parents,'keyDirectory'=>$parents];
        if($data['vaultLocation']==='imported')$parents['vaultDirectory']=$source['source']['legacyKeyFolder'];
        if($data['keyLocation']==='imported')$parents['keyDirectory']=$source['source']['legacyKeyFolder'];
        $checked=$this->store->reviewStorageMove($target,IPS_GetKernelDir(),$parents);
        if($checked['to']!==$from){
            if(PHP_OS_FAMILY==='Windows'&&!$data['privateACLConfirmed'])throw new RuntimeException('Confirm private Windows folder permissions before using imported locations.');
            $persistence=SecretsBackendNativePlatform::persistence($checked['to']['vaultDirectory'],$checked['to']['keyDirectory'],IPS_GetKernelDir());
            if(($persistence['vault']['confirmationRequired']||$persistence['keys']['confirmationRequired'])&&!$data['persistenceConfirmed'])throw new RuntimeException('Confirm that the imported locations survive a container restart.');
        }
        $storage=$checked+['id'=>SecretsBackendCodec::uuid(),'kernel'=>IPS_GetKernelDir(),'legacyParent'=>$parents,'choices'=>['vault'=>$data['vaultLocation'],'keys'=>$data['keyLocation']]];
        $expected=$this->store->opaque('legacy-result:'.SecretsBackendNativeStore::canonical($plan['trees']));
        $c=['session'=>$this->session,'head'=>$current['head'],'source'=>$source,'policy'=>$data['policy'],'storage'=>$storage,'expected'=>$expected,'expires'=>time()+300];$review=$this->legacyReview($c,$current['state']);
        $id=SecretsBackendCodec::b64(random_bytes(32));$digest=$this->store->opaque('legacy-import:'.SecretsBackendNativeStore::canonical($c));$this->store->put($id,'legacy-import',$c,$c['expires']);
        return ['candidate'=>$id,'digest'=>$digest,'review'=>$review];
    }
    private function legacyResult(array $op,array $validated): array
    {
        $c=$this->store->get($op['candidate'],'legacy-import');
        $actual=array_intersect_key($validated['state']['vault'],array_flip(['global','local']));
        if(!hash_equals($c['expected'],$this->store->opaque('legacy-result:'.SecretsBackendNativeStore::canonical($actual))))throw new RuntimeException('Import committed but verification needs review. Do not repeat blindly.');
        $this->store->delete($op['candidate']);
        return ['legacyImported'=>true,'verified'=>true,'summary'=>$op['review']['summary'],'storage'=>$c['storage']['to'],'backup'=>$op['backup'],'recoveryKey'=>$op['backupKey']];
    }
    /** Keep the old vault read lock until the destination's durable commit finishes. */
    public function commit(array $op,callable $commit): array
    {
        if($op['kind']!=='nativeLegacyImport')return $commit();
        $current=$this->store->read();$c=$this->legacyCandidate($op['candidate'],$op['digest'],$current['state']);
        return SecretsBackendLegacyImport::withSnapshot($c['source']['source']['id'],$this->legacyLimit(),function(array $source)use($c,$commit):array{
            if(!hash_equals($source['fingerprint'],$c['source']['fingerprint']))throw new RuntimeException('The old vault changed after review. Review a new import.');
            $this->legacyCommitSource=$source;try{return $commit();}finally{$this->legacyCommitSource=null;}
        });
    }
    public function metadata(array $state): array
    {
        $received=[];foreach($state['native']['received']as$id=>$r)if(!isset($state['native']['trees'][$id]))$received[]=['id'=>$id,'owner'=>$r['owner'],'revision'=>$r['revision'],'at'=>$r['at'],'entries'=>SecretsBackendTree::listing($r['node'])];
        $owned=[];foreach($state['native']['trees']as$id=>$r)$owned[]=['id'=>$id,'owner'=>$r['owner'],'epoch'=>$r['epoch'],'revision'=>$r['revision'],'frozen'=>$r['frozen'],'entries'=>SecretsBackendTree::listing($r['node'])];
        $machines=[];foreach($state['native']['machines']as$m){unset($m['hash']);$machines[]=$m;}
        return ['legacyImports'=>array_values($state['native']['legacyImports']??[]),'backupOrigin'=>$state['policy']['backupOrigin']??null,'primaryOrigin'=>$state['policy']['origin'],'info'=>$this->store->metadata(),'storage'=>$this->store->storagePaths(),'peerEndpoint'=>$this->peer->descriptor()['endpoint'],'peerDescriptor'=>$this->peer->descriptor(),
            'globalTreeId'=>$state['native']['globalTreeId'],'globalWritable'=>$state['native']['globalWritable'],'ownedTrees'=>$owned,'transfers'=>array_map(static fn($t)=>array_diff_key($t,['node'=>true]),$state['native']['transfers']),
            'peers'=>array_values($state['pairing']['peers']),'received'=>$received,'machines'=>$machines,'queuedJobs'=>count($state['outbox']['jobs']),
            'providers'=>array_values(array_map(static fn($p)=>SecretsBackendNativeEffects::targetWritable($state,$p)?$p:array_replace($p,['status'=>'OWNER_CHANGED']),$state['native']['providers'])),'effects'=>array_map(static fn($e)=>array_intersect_key($e,array_flip(['id','providerId','state','reason','createdAt','httpStatus','attempts'])),$state['native']['effects']),
            'hardwareProfile'=>['version'=>$state['policy']['management']['settings']['HardwareTrustVersion'],'fingerprints'=>$state['policy']['management']['files']['HardwareRoots'],'aaguids'=>json_decode($state['policy']['management']['settings']['HardwareAAGUIDs'],true)],
            'outbox'=>array_map(static fn($j)=>array_intersect_key($j,array_flip(['id','receiverId','kind','sequence','status'])),$state['outbox']['jobs'])];
    }
}
