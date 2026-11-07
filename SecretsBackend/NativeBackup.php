<?php
declare(strict_types=1);
require_once __DIR__ . '/NativeStore.php';
require_once __DIR__ . '/NativePeer.php';
require_once __DIR__ . '/Tree.php';
require_once __DIR__ . '/../SecretsFrontend/Configuration.php';

final class SecretsBackendNativeBackup
{
    /** Recover all values and conflict variants locally without selecting a Global winner. */
    public static function localRecoveryNode(array $backup):array
    {
        $state=$backup['state'];$conflicts=isset($state['native']['sharedGlobal'])?SecretsBackendSharedGlobal::view($state['native']['sharedGlobal'])['conflicts']:[];
        $entries=[['key'=>$conflicts?'globalProjection':'global','node'=>$state['vault']['global']],['key'=>'local','node'=>$state['vault']['local']]];
        if($conflicts){
            $groups=[];
            foreach(array_chunk($conflicts,100)as$i=>$batch){$records=[];
                foreach($batch as$c){$versions=[];foreach($c['versions']as$v)$versions[]=['key'=>$v['id'],'node'=>['type'=>'object','entries'=>[
                    ['key'=>'platforms','node'=>['type'=>'string','value'=>implode(', ',$v['platforms'])]],
                    ['key'=>'deleted','node'=>['type'=>'boolean','value'=>$v['node']===null]],
                    ['key'=>'value JSON','node'=>['type'=>'string','value'=>SecretsBackendCodec::json($v['node']===null?null:SecretsBackendTree::value($v['node']))]]
                ]]];
                $records[]=['key'=>$c['digest'],'node'=>['type'=>'object','entries'=>[['key'=>'path','node'=>['type'=>'string','value'=>SecretsBackendCodec::json($c['path'])]],['key'=>'versions','node'=>['type'=>'object','entries'=>$versions]]]]];}
                $groups[]=['key'=>'Group '.($i+1),'node'=>['type'=>'object','entries'=>$records]];
            }
            $entries[]=['key'=>'Global conflict variants','node'=>['type'=>'object','entries'=>$groups]];
            $entries[]=['key'=>'Global causal history','node'=>['type'=>'string','value'=>SecretsBackendNativeStore::canonical($state['native']['sharedGlobal'])]];
        }
        return ['type'=>'object','entries'=>$entries];
    }
    public static function encrypt(SecretsBackendNativeStore $store,string $recoveryKey,?array $validated=null): string
    {
        $key=SecretsBackendCodec::unb64($recoveryKey,32);$material=$store->backupMaterial($validated);
        $header=['format'=>'SECB.Backup.1','vaultId'=>$material['identity']['deploymentId'],'at'=>gmdate('c')];$iv=random_bytes(12);$tag='';
        $cipher=openssl_encrypt(SecretsBackendCodec::json($material),'aes-256-gcm',$key,OPENSSL_RAW_DATA,$iv,$tag,SecretsBackendNativeStore::canonical($header),16);
        if(!is_string($cipher))throw new RuntimeException('Encrypted backup could not be created.');
        return SecretsBackendCodec::json($header+['iv'=>SecretsBackendCodec::b64($iv),'tag'=>SecretsBackendCodec::b64($tag),'data'=>SecretsBackendCodec::b64($cipher)]);
    }
    public static function decrypt(string $bytes,string $recoveryKey,int $limit): array
    {
        $b=SecretsFrontendConfiguration::decodeBounded($bytes,$limit*3+32768,16);SecretsBackendNativePeer::exact($b,['format','vaultId','at','iv','tag','data']);
        if($b['format']!=='SECB.Backup.1')throw new RuntimeException('Unsupported native backup format.');
        $header=array_intersect_key($b,array_flip(['format','vaultId','at']));
        $plain=openssl_decrypt(SecretsBackendCodec::unb64($b['data']),'aes-256-gcm',SecretsBackendCodec::unb64($recoveryKey,32),OPENSSL_RAW_DATA,SecretsBackendCodec::unb64($b['iv'],12),SecretsBackendCodec::unb64($b['tag'],16),SecretsBackendNativeStore::canonical($header));
        if(!is_string($plain)||strlen($plain)>$limit*2+32768)throw new RuntimeException('Backup authentication failed or the backup exceeds this installation’s memory budget.');
        $m=SecretsFrontendConfiguration::decodeBounded($plain,$limit*2+32768,96);
        if(($m['identity']['deploymentId']??'')!==$b['vaultId']||!isset($m['state']['vault']['global'],$m['state']['vault']['local'],$m['keys']))throw new RuntimeException('Incomplete authenticated backup.');
        foreach(['global','local']as$scope){
            $node=$m['state']['vault'][$scope];
            if(($node['type']??'')!=='object')throw new RuntimeException('Invalid backup secret hierarchy.');
            $normalized=SecretsBackendTree::parseBounded(SecretsBackendCodec::json(SecretsBackendTree::value($node)),$limit);
            if(SecretsBackendNativePeer::digest($node)!==SecretsBackendNativePeer::digest($normalized))throw new RuntimeException('Invalid backup secret hierarchy.');
        }
        if(($m['head']['digest']??'')!==SecretsBackendNativeStore::stateDigest($m['state']))throw new RuntimeException('Backup state/head mismatch.');
        return $m;
    }
}

/** Authenticated, bounded chunks keep browser requests below the existing 64-KiB cap. */
final class SecretsBackendNativeUploads
{
    public function __construct(private SecretsBackendNativeStore $store,private string $session){}
    private function record(string $id): array { SecretsBackendNativePeer::uuid($id);$r=$this->store->get('upload:'.$id,'upload');if($r['session']!==$this->session)throw new RuntimeException('Upload belongs to another session.');return $r; }
    public function begin(int $length,string $digest): array
    {
        if($length<1||$length>$this->store->metadata()['capacityBytes']*3+32768||!preg_match('/^[a-f0-9]{64}$/D',$digest))throw new RuntimeException('Backup upload exceeds the bounded native capacity.');
        $id=SecretsBackendCodec::uuid();$this->store->put('upload:'.$id,'upload',['session'=>$this->session,'length'=>$length,'digest'=>$digest,'received'=>0,'next'=>0,'finished'=>false],time()+600);
        return ['uploadId'=>$id,'chunkBytes'=>32768];
    }
    public function chunk(string $id,int $index,string $encoded): array
    {
        $r=$this->record($id);$bytes=SecretsBackendCodec::unb64($encoded);
        if($r['finished']||$index!==$r['next']||strlen($bytes)>32768||$r['received']+strlen($bytes)>$r['length']||$index>512)throw new RuntimeException('Upload chunk is out of order or oversized.');
        $file=$this->store->stagingDirectory().'/up-'.$id.'-'.$index;
        if(is_file($file)){if(!hash_equals(hash('sha256',SecretsBackendNativePlatform::readPrivate($file,32768)),hash('sha256',$bytes)))throw new RuntimeException('Conflicting repeated upload chunk.');}
        else SecretsBackendNativePlatform::writeNew($file,$bytes);
        $r['received']+=strlen($bytes);++$r['next'];$this->store->replace('upload:'.$id,'upload',$r,time()+600);return ['received'=>$r['received']];
    }
    public function finish(string $id): array
    {
        $r=$this->record($id);if($r['received']!==$r['length'])throw new RuntimeException('Backup upload is incomplete.');
        $bytes='';for($i=0;$i<$r['next'];++$i)$bytes.=SecretsBackendNativePlatform::readPrivate($this->store->stagingDirectory().'/up-'.$id.'-'.$i,32768);
        if(!hash_equals($r['digest'],hash('sha256',$bytes)))throw new RuntimeException('Backup upload digest mismatch.');
        $file=$this->store->stagingDirectory().'/up-'.$id.'-final';if(!is_file($file))SecretsBackendNativePlatform::writeNew($file,$bytes);
        $r['finished']=true;$this->store->replace('upload:'.$id,'upload',$r,time()+600);return ['uploadId'=>$id,'digest'=>$r['digest'],'bytes'=>$r['length']];
    }
    public function read(string $id): string
    {
        $r=$this->record($id);if(!$r['finished'])throw new RuntimeException('Finish the complete upload before review.');
        $bytes=SecretsBackendNativePlatform::readPrivate($this->store->stagingDirectory().'/up-'.$id.'-final',$r['length']);
        if(!hash_equals($r['digest'],hash('sha256',$bytes)))throw new RuntimeException('Reviewed upload changed.');return $bytes;
    }
    public function remove(string $id): void
    {
        $r=$this->record($id);for($i=0;$i<$r['next'];++$i){$p=$this->store->stagingDirectory().'/up-'.$id.'-'.$i;if(is_file($p)&&!is_link($p))unlink($p);}
        $p=$this->store->stagingDirectory().'/up-'.$id.'-final';if(is_file($p)&&!is_link($p))unlink($p);$this->store->delete('upload:'.$id);
    }
}
