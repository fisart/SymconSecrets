<?php
declare(strict_types=1);
require_once __DIR__.'/NativePlatform.php';
require_once __DIR__.'/Codec.php';

/** Separate private credentials and causal checkpoint. Never contains secret values. */
final class SecretsBackendEmergencyCapsule
{
    public function __construct(private string $directory) { $this->directory=SecretsBackendNativePlatform::directory($directory); }
    public function exists(): bool { return is_file($this->directory.'/access.sealed'); }
    private function locked(callable $operation,bool $create=false) {
        if($create)SecretsBackendNativePlatform::makePrivate($this->directory);
        if(!is_dir($this->directory)||is_link($this->directory))throw new RuntimeException('Emergency access is not provisioned.');
        $file=$this->directory.'/access.lock';
        if($create&&!file_exists($file))SecretsBackendNativePlatform::writeNew($file,'');
        SecretsBackendNativePlatform::readPrivate($file,0);$h=fopen($file,'r+b');
        if($h===false)throw new RuntimeException('Emergency storage unavailable.');
        try{if(!flock($h,LOCK_EX|LOCK_NB))throw new RuntimeException('Emergency storage busy.');return $operation();}
        finally{flock($h,LOCK_UN);fclose($h);}
    }
    private function publish(string $name,string $bytes): void {
        $path=$this->directory.'/'.$name;if(is_link($path))throw new RuntimeException('Unsafe emergency storage.');
        $tmp=$this->directory.'/tmp-'.SecretsBackendCodec::uuid();
        try{SecretsBackendNativePlatform::writeNew($tmp,$bytes);if(!rename($tmp,$path))throw new RuntimeException('Emergency publication failed.');SecretsBackendNativePlatform::syncDirectory($this->directory);}
        finally{if(is_file($tmp))unlink($tmp);}
    }
    private function decode(): array {
        $key=SecretsBackendNativePlatform::readPrivate($this->directory.'/access.key',32);if(strlen($key)!==32)throw new RuntimeException('Emergency key invalid.');
        $bytes=SecretsBackendNativePlatform::readPrivate($this->directory.'/access.sealed',131072);
        if(strlen($bytes)<40)throw new RuntimeException('Emergency credentials invalid.');
        $plain=sodium_crypto_secretbox_open(substr($bytes,24),substr($bytes,0,24),$key);
        if(!is_string($plain))throw new RuntimeException('Emergency credentials invalid.');
        $s=json_decode($plain,true,32,JSON_THROW_ON_ERROR);
        if(!is_array($s)||($s['format']??'')!=='SECB.EmergencyAccess.1')throw new RuntimeException('Emergency format invalid.');return $s;
    }
    private function encode(array $s): void {
        $key=SecretsBackendNativePlatform::readPrivate($this->directory.'/access.key',32);$nonce=random_bytes(24);
        $this->publish('access.sealed',$nonce.sodium_crypto_secretbox(SecretsBackendCodec::json($s),$nonce,$key));
    }
    /** Called before permission-changing local commits; an interrupted update fails closed. */
    public function invalidate(bool $manual=false): void {
        if(!$this->exists())return;
        $this->locked(function()use($manual):void{$name=$manual?'manual-stop':'blocked';if(!file_exists($this->directory.'/'.$name))$this->publish($name,'blocked');});
    }
    public function load(string $binding): array {
        return $this->locked(function()use($binding):array{
            if(file_exists($this->directory.'/blocked')||file_exists($this->directory.'/manual-stop'))throw new RuntimeException('Emergency access disabled.');
            $s=$this->decode();if(!hash_equals($s['binding'],$binding)||!$s['enabled'])throw new RuntimeException('Emergency binding or permission changed.');return $s;
        });
    }
    /** Disabling remote authority never erases already observed Global version evidence. */
    public function checkpoint(string $source): array {
        return $this->locked(function()use($source):array{
            $s=$this->decode();if(!hash_equals($s['source'],$source))throw new RuntimeException('Emergency source identity changed.');return $s['floor'];
        });
    }
    /** Caller holds the active vault snapshot lock. Only a reviewed import may create keys. */
    public function synchronize(array $state,string $binding,array $clients,bool $readAllowed,array $stamp,bool $approvedCreate=false): bool {
        if(!$clients&&!$this->exists())return false;
        return $this->locked(function()use($state,$binding,$clients,$readAllowed,$stamp,$approvedCreate):bool{
            $key=$this->directory.'/access.key';
            if(!file_exists($key)){
                if(!$approvedCreate||$this->exists())throw new RuntimeException('Emergency key missing; re-provision explicitly.');
                SecretsBackendNativePlatform::writeNew($key,random_bytes(32));SecretsBackendNativePlatform::syncDirectory($this->directory);
            }
            $old=$this->exists()?$this->decode():null;
            if($old!==null&&$old['source']!==$state['native']['vaultId'])throw new RuntimeException('Emergency source identity changed.');
            $floor=$old['floor']??['clock'=>[],'digest'=>null];
            $relation=SecretsBackendEmergency::compare($stamp['clock'],$floor['clock']);
            if($relation===0&&$floor['digest']!==null&&!hash_equals($floor['digest'],$stamp['digest']))throw new SecretsBackendEmergencyRefused('INCONSISTENT_HISTORY');
            if($relation===0||$relation===1)$floor=['clock'=>$stamp['clock'],'digest'=>$stamp['digest']];
            $authorization=hash('sha256',SecretsBackendNativeStore::canonical([$binding,$clients,$readAllowed]));
            $s=['format'=>'SECB.EmergencyAccess.1','source'=>$state['native']['vaultId'],'binding'=>$binding,'authorization'=>$authorization,'enabled'=>$readAllowed&&count($clients)>0,'clients'=>$clients,'floor'=>$floor,'checkpointAt'=>time()];
            if($old!==null&&$old['floor']===$s['floor']&&$old['authorization']===$authorization&&$old['enabled']===$s['enabled'])$s['checkpointAt']=$old['checkpointAt'];
            if($s!==$old)$this->encode($s);
            if(file_exists($this->directory.'/blocked')){unlink($this->directory.'/blocked');SecretsBackendNativePlatform::syncDirectory($this->directory);}
            if($approvedCreate&&file_exists($this->directory.'/manual-stop')){unlink($this->directory.'/manual-stop');SecretsBackendNativePlatform::syncDirectory($this->directory);}
            return $relation===0||$relation===1;
        },$approvedCreate);
    }
    /** Remember authenticated newer observations even if a subsequent read fails. */
    public function observe(string $binding,string $authorization,array $stamp): void {
        $this->locked(function()use($binding,$authorization,$stamp):void{
            if(file_exists($this->directory.'/blocked')||file_exists($this->directory.'/manual-stop'))throw new RuntimeException('Emergency access changed.');
            $s=$this->decode();if(!$s['enabled']||!hash_equals($s['binding'],$binding)||!hash_equals($s['authorization'],$authorization))throw new RuntimeException('Emergency authority changed.');
            $relation=SecretsBackendEmergency::compare($stamp['clock'],$s['floor']['clock']);
            if($relation===0&&$s['floor']['digest']!==null&&!hash_equals($s['floor']['digest'],$stamp['digest']))throw new SecretsBackendEmergencyRefused('INCONSISTENT_HISTORY');
            if($relation===-1)return;
            $floor=['clock'=>$stamp['clock'],'digest'=>$stamp['digest']];
            if($relation===2){$floor=$s['floor'];foreach($stamp['clock']as$id=>$n){$old=$floor['clock'][$id]??'0';if(strlen($n)>strlen($old)||(strlen($n)===strlen($old)&&strcmp($n,$old)>0))$floor['clock'][$id]=$n;}ksort($floor['clock']);$floor['digest']=null;}
            if($s['floor']!==$floor){$s['floor']=$floor;$s['checkpointAt']=time();$this->encode($s);}
        });
    }
    /** Revalidate revocation/binding after network I/O before exposing a result. */
    public function accept(string $binding,string $authorization,array $stamp): void {
        $this->locked(function()use($binding,$authorization,$stamp):void{
            if(file_exists($this->directory.'/blocked')||file_exists($this->directory.'/manual-stop'))throw new RuntimeException('Emergency access changed during read.');
            $s=$this->decode();if(!$s['enabled']||!hash_equals($s['binding'],$binding)||!hash_equals($s['authorization'],$authorization))throw new RuntimeException('Emergency access changed during read.');
            $relation=SecretsBackendEmergency::compare($stamp['clock'],$s['floor']['clock']);
            if(!in_array($relation,[0,1],true)||($relation===0&&$s['floor']['digest']!==null&&!hash_equals($s['floor']['digest'],$stamp['digest'])))throw new RuntimeException('Remote result is older than known Global state.');
            $next=['clock'=>$stamp['clock'],'digest'=>$stamp['digest']];if($s['floor']!==$next){$s['floor']=$next;$s['checkpointAt']=time();$this->encode($s);}
        });
    }
}
