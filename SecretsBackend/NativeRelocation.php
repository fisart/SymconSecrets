<?php
declare(strict_types=1);
require_once __DIR__.'/NativePlatform.php';

/** Crash-resumable, authenticated redirects. The old copy is retained, never reused for writes. */
final class SecretsBackendNativeRelocation
{
    public static function marker(array $paths): string { return $paths['vaultDirectory'].'/relocation-'.hash('sha256', SecretsBackendCodec::json($paths)).'.json'; }
    public static function validate(array $from,array $to,string $kernel,bool $empty=true,string|array|null $legacyParent=null): array
    {
        $to=SecretsBackendNativePlatform::paths($to['vaultDirectory'],$to['keyDirectory'],$kernel,false,$legacyParent);
        foreach($to as $kind=>$path){
            foreach($from as $oldKind=>$old){
                if($kind===$oldKind&&$path===$old)continue;
                if(SecretsBackendNativePlatform::contains($old,$path)||SecretsBackendNativePlatform::contains($path,$old))throw new RuntimeException('New storage folders must be separate from both current storage folders.');
            }
            if($empty&&$path!==$from[$kind]&&is_dir($path)&&count(scandir($path)?:[])!==2)throw new RuntimeException('The imported storage subfolder already contains files. Choose current locations or use a new empty subfolder.');
        }
        return $to;
    }
    public static function inventory(string $root): array
    {
        $files=[];$directories=[];$bytes=0;
        $walk=static function(string $relative)use(&$walk,&$files,&$directories,&$bytes,$root):void{
            foreach(scandir($root.($relative===''?'':'/'.$relative))?:[] as $name){
                if($name==='.'||$name==='..')continue;
                $r=($relative===''?'':$relative.'/').$name;$p=$root.'/'.$r;
                if(is_link($p))throw new RuntimeException('Storage relocation refuses symbolic links.');
                if(is_dir($p)){$directories[]=$r;if(count($directories)>128)throw new RuntimeException('Too many storage subfolders.');$walk($r);}
                elseif(is_file($p)){
                    if($relative===''&&($name==='native.lock'||str_starts_with($name,'relocation-')||str_starts_with($name,'relocated-')||str_starts_with($name,'tmp-')))continue;
                    $size=filesize($p);if($size===false||$size>16*1024*1024||($bytes+=$size)>128*1024*1024||count($files)>=1024)throw new RuntimeException('Storage relocation exceeds its bounded copy budget.');
                    if(PHP_OS_FAMILY!=='Windows'&&(fileperms($p)&0077)!==0)throw new RuntimeException('Storage relocation requires private source files.');
                    $hash=hash_file('sha256',$p);if(!is_string($hash))throw new RuntimeException('Cannot verify source storage.');$files[$r]=['bytes'=>$size,'sha256'=>$hash];
                }else throw new RuntimeException('Unsupported storage entry.');
            }
        };$walk('');ksort($files);sort($directories);return ['directories'=>$directories,'files'=>$files];
    }
    private static function publish(string $path,string $bytes): void
    {
        $temp=dirname($path).'/tmp-'.SecretsBackendCodec::uuid();SecretsBackendNativePlatform::writeNew($temp,$bytes);
        if(file_exists($path)||is_link($path)||!rename($temp,$path))throw new RuntimeException('Storage handoff publication failed.');SecretsBackendNativePlatform::syncDirectory(dirname($path));
    }
    public static function prepare(array $move,string $vault,callable $sign): array
    {
        $from=$move['from'];$to=$move['to'];self::validate($from,$to,$move['kernel'],true,$move['legacyParent']);
        $manifest=['version'=>'SECB.Relocation.1','id'=>$move['id'],'vault'=>$vault,'from'=>$from,'to'=>$to,'inventory'=>[]];
        foreach($from as $kind=>$root)if($root!==$to[$kind])$manifest['inventory'][$kind]=self::inventory($root);
        $manifest['mac']=$sign('storage-relocation:'.SecretsBackendCodec::json($manifest));
        self::publish(self::marker($from),SecretsBackendCodec::json($manifest));return $manifest;
    }
    public static function read(array $paths,string $vault,callable $sign): ?array
    {
        $path=self::marker($paths);if(!file_exists($path)&&!is_link($path))return null;
        $m=json_decode(SecretsBackendNativePlatform::readPrivate($path,524288),true,32,JSON_THROW_ON_ERROR);$mac=$m['mac']??'';unset($m['mac']);
        if(!is_string($mac)||!hash_equals($sign('storage-relocation:'.SecretsBackendCodec::json($m)),$mac)||($m['version']??'')!=='SECB.Relocation.1'||($m['vault']??'')!==$vault||($m['from']??null)!==$paths)throw new RuntimeException('Storage handoff authentication failed.');
        $m['mac']=$mac;return $m;
    }
    private static function copy(string $source,string $target,array $entry): void
    {
        if(is_link($target))throw new RuntimeException('Storage handoff refuses destination links.');
        if(file_exists($target)){
            if(!is_file($target)||(PHP_OS_FAMILY!=='Windows'&&(fileperms($target)&0077)!==0))throw new RuntimeException('Copied storage is not private.');
            if(filesize($target)!==$entry['bytes']||!hash_equals($entry['sha256'],hash_file('sha256',$target)))throw new RuntimeException('Interrupted storage copy conflicts with existing destination files.');return;
        }
        if(is_link($source)||!is_file($source)||filesize($source)!==$entry['bytes']||!hash_equals($entry['sha256'],hash_file('sha256',$source)))throw new RuntimeException('Frozen source storage changed during handoff.');
        $temp=dirname($target).'/tmp-'.SecretsBackendCodec::uuid();$mask=umask(0077);try{$out=fopen($temp,'x+b');}finally{umask($mask);}$in=fopen($source,'rb');
        if($in===false||$out===false){if(is_resource($in))fclose($in);if(is_resource($out))fclose($out);throw new RuntimeException('Cannot open storage copy.');}
        try{
            if(!chmod($temp,0600))throw new RuntimeException('Cannot protect copied storage.');
            while(!feof($in)){$chunk=fread($in,65536);if($chunk===false)throw new RuntimeException('Storage copy read failed.');for($at=0;$at<strlen($chunk);){$n=fwrite($out,substr($chunk,$at));if(!$n)throw new RuntimeException('Storage copy write failed.');$at+=$n;}}
            if(!fflush($out)||!fsync($out))throw new RuntimeException('Storage copy synchronization failed.');
        }finally{fclose($in);fclose($out);}
        if(filesize($temp)!==$entry['bytes']||!hash_equals($entry['sha256'],hash_file('sha256',$temp)))throw new RuntimeException('Storage copy verification failed.');
        if(file_exists($target)||!rename($temp,$target))throw new RuntimeException('Storage copy publication failed.');SecretsBackendNativePlatform::syncDirectory(dirname($target));
    }
    /** Called while holding the old vault lock; a completed receipt prevents stale recopying. */
    public static function resume(array $m,callable $sign,?callable $fault=null): array
    {
        $to=$m['to'];foreach($to as $path)if(SecretsBackendNativePlatform::directory($path)!==$path)throw new RuntimeException('Storage handoff destination changed.');
        $receipt=$to['vaultDirectory'].'/relocated-'.$m['id'].'.json';$expected=$sign('storage-relocated:'.SecretsBackendCodec::json($m));
        if(file_exists($receipt)||is_link($receipt)){
            if(!hash_equals($expected,SecretsBackendNativePlatform::readPrivate($receipt,64)))throw new RuntimeException('Storage handoff receipt is corrupt.');return $to;
        }
        foreach($m['inventory'] as $kind=>$inventory){$root=$to[$kind];SecretsBackendNativePlatform::makePrivate($root);
            $existing=self::inventory($root);
            foreach($existing['files'] as $relative=>$entry)if(!isset($inventory['files'][$relative])||$inventory['files'][$relative]!==$entry)throw new RuntimeException('Destination contains files outside the authenticated storage copy.');
            foreach($existing['directories'] as $relative)if(!in_array($relative,$inventory['directories'],true))throw new RuntimeException('Destination contains unreviewed subfolders.');
            foreach($inventory['directories'] as $relative)SecretsBackendNativePlatform::makePrivate($root.'/'.$relative);
            foreach($inventory['files'] as $relative=>$entry){self::copy($m['from'][$kind].'/'.$relative,$root.'/'.$relative,$entry);if($fault!==null)$fault('relocation_copy');}
        }
        $lock=$to['vaultDirectory'].'/native.lock';if(!is_file($lock))self::publish($lock,'');SecretsBackendNativePlatform::readPrivate($lock,0);
        if($fault!==null)$fault('relocation_before_receipt');self::publish($receipt,$expected);return $to;
    }
}
