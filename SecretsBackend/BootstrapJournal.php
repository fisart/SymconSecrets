<?php
declare(strict_types=1);
require_once __DIR__ . '/BootstrapVerifier.php';
require_once __DIR__ . '/NativePlatform.php';

/** Shared immutable decisions. All callers hold this journal lock through publication. */
final class SecretsBootstrapJournal
{
    private string $key;
    private int $depth = 0;
    private static array $held = [];
    public function __construct(private string $data,private string $keys,bool $create=false,private $fault=null)
    {
        $pair = SecretsBackendNativePlatform::paths($data,$keys,'/unused-bootstrap-kernel');
        $this->data=$pair['vaultDirectory']; $this->keys=$pair['keyDirectory'];
        if ($create) { SecretsBackendNativePlatform::makePrivate($this->data); SecretsBackendNativePlatform::makePrivate($this->keys); }
        else { foreach ([$this->data,$this->keys] as $p) if (!is_dir($p)) throw new RuntimeException('Bootstrap journal is unavailable; recovery is required.'); }
        SecretsBackendNativePlatform::makePrivate($this->data); SecretsBackendNativePlatform::makePrivate($this->keys);
        // The lock file is not an authority record. fopen(c+) is serialized by flock.
        $this->locked(function()use($create):void{
            $path=$this->keys.'/journal.key';
            if (!file_exists($path)) {
                if (!$create || (glob($this->data.'/*.sealed')?:[]) || (glob($this->data.'/tmp-*')?:[]) || (glob($this->keys.'/tmp-*')?:[])) throw new RuntimeException('Missing bootstrap journal key; it is never regenerated for existing records.');
                $temp=$this->keys.'/tmp-'.SecretsBackendCodec::uuid(); SecretsBackendNativePlatform::writeNew($temp,random_bytes(32));
                if (!rename($temp,$path)) throw new RuntimeException('Bootstrap key publication uncertain.');
                SecretsBackendNativePlatform::syncDirectory($this->keys);
            }
            $this->key=SecretsBackendNativePlatform::readPrivate($path,32);
            if(strlen($this->key)!==32)throw new RuntimeException('Invalid bootstrap journal key.');
        });
    }
    public static function forKernel(string $kernel,bool $create=false): self
    {
        $base=rtrim(str_replace('\\','/',$kernel),'/');
        return new self($base.'/secrets-native-data/bootstrap',$base.'/secrets-native-keys/bootstrap',$create);
    }
    public function locked(callable $fn)
    {
        if(isset(self::$held[$this->data])){++$this->depth;try{return $fn();}finally{--$this->depth;}}
        $path=$this->data.'/journal.lock'; if(is_link($path))throw new RuntimeException('Unsafe journal lock.');
        $mask=umask(0077);try{$h=fopen($path,'c+b');}finally{umask($mask);}
        if($h===false)throw new RuntimeException('Cannot open bootstrap coordinator.');
        try{if(!flock($h,LOCK_EX))throw new RuntimeException('Cannot lock bootstrap coordinator.');$this->depth++;self::$held[$this->data]=true;return $fn();}
        finally{unset(self::$held[$this->data]);$this->depth=0;flock($h,LOCK_UN);fclose($h);}
    }
    private function name(string $name): string
    {
        if(!preg_match('/^[a-z0-9_-]{1,160}$/D',$name))throw new RuntimeException('Invalid journal record name.');
        return $this->data.'/'.$name.'.sealed';
    }
    public function read(string $name): ?array
    {
        if(!$this->depth)throw new RuntimeException('Journal lock required.');
        $path=$this->name($name);if(!file_exists($path)&&!is_link($path))return null;
        $wire=SecretsFrontendConfiguration::decodeBounded(SecretsBackendNativePlatform::readPrivate($path,262144),262144,8);
        SecretsBootstrapVerifier::exact($wire,['iv','tag','data']);
        $plain=openssl_decrypt(SecretsBackendCodec::unb64($wire['data']),'aes-256-gcm',$this->key,OPENSSL_RAW_DATA,SecretsBackendCodec::unb64($wire['iv'],12),SecretsBackendCodec::unb64($wire['tag'],16),'SECF.BOOTSTRAP.JOURNAL.1:'.$name);
        if(!is_string($plain))throw new RuntimeException('Bootstrap journal authentication failed.');
        // Re-establish directory sync after an acknowledgement was lost at publication.
        SecretsBackendNativePlatform::syncDirectory($this->data);
        return SecretsFrontendConfiguration::decodeBounded($plain,196608,48);
    }
    public function write(string $name,array $value): array
    {
        if(!$this->depth)throw new RuntimeException('Journal lock required.');
        $old=$this->read($name);if($old!==null){if(SecretsBootstrapVerifier::digest($old)!==SecretsBootstrapVerifier::digest($value))throw new RuntimeException('Immutable bootstrap decision already exists.');return $old;}
        if((glob($this->data.'/tmp-*')?:[]) || count(glob($this->data.'/*.sealed')?:[])>=512)throw new RuntimeException('Bootstrap journal requires recovery or archival; no new decision accepted.');
        $plain=SecretsBackendCodec::json($value);if(strlen($plain)>196608)throw new RuntimeException('Bootstrap record too large.');
        $iv=random_bytes(12);$tag='';$cipher=openssl_encrypt($plain,'aes-256-gcm',$this->key,OPENSSL_RAW_DATA,$iv,$tag,'SECF.BOOTSTRAP.JOURNAL.1:'.$name,16);
        if(!is_string($cipher))throw new RuntimeException('Cannot encrypt bootstrap record.');
        $wire=SecretsBackendCodec::json(['iv'=>SecretsBackendCodec::b64($iv),'tag'=>SecretsBackendCodec::b64($tag),'data'=>SecretsBackendCodec::b64($cipher)]);
        $temp=$this->data.'/tmp-'.SecretsBackendCodec::uuid();SecretsBackendNativePlatform::writeNew($temp,$wire);
        if($this->fault!==null)($this->fault)('before_publish');
        if(file_exists($this->name($name))||!rename($temp,$this->name($name)))throw new RuntimeException('Bootstrap decision publication is UNKNOWN.');
        if($this->fault!==null)($this->fault)('after_publish');
        SecretsBackendNativePlatform::syncDirectory($this->data);
        if($this->fault!==null)($this->fault)('after_sync');
        return $this->read($name)??throw new RuntimeException('Bootstrap decision missing after publication.');
    }
    public function decisions(): array
    {
        $out=[];$files=glob($this->data.'/decision-*.sealed')?:[];
        if(count($files)>128)throw new RuntimeException('Bootstrap decision history requires archival.');
        foreach($files as $f){$name=basename($f,'.sealed');$out[]=$this->read($name);}return $out;
    }
    public function reserve(array $decision): void
    {
        foreach($this->decisions()as$d){
            if(($d['status']??'')!=='ACCEPTED'||$d['intent']===$decision['intent'])continue;
            $a=$d['plan'];$b=$decision['plan'];
            if($a['backend']>0&&$a['backend']===$b['backend'])throw new RuntimeException('Backend reserved by an accepted operation.');
            foreach(['vaultDirectory','keyDirectory']as$x)foreach(['vaultDirectory','keyDirectory']as$y)
                if(SecretsBackendNativePlatform::contains($a[$x],$b[$y])||SecretsBackendNativePlatform::contains($b[$y],$a[$x]))throw new RuntimeException('Storage reserved by an accepted operation.');
        }
    }
    public function fence(string $operation,string $runtime): string
    {
        SecretsBootstrapVerifier::uuid($operation);$files=glob($this->data.'/worker-'.$operation.'-*.sealed')?:[];sort($files,SORT_STRING);
        $previous=$files?$this->read(basename(end($files),'.sealed')):null;
        if($previous!==null&&$previous['runtime']===$runtime)return $previous['generation'];
        $generation=SecretsBackendCodec::increment($previous['generation']??'0');
        $this->write('worker-'.$operation.'-'.str_pad($generation,16,'0',STR_PAD_LEFT),['runtime'=>$runtime,'generation'=>$generation]);return $generation;
    }
    public function checkFence(string $operation,string $runtime,string $generation): void
    {
        $files=glob($this->data.'/worker-'.$operation.'-*.sealed')?:[];sort($files,SORT_STRING);
        $current=$files?$this->read(basename(end($files),'.sealed')):null;
        if($current===null||$current['runtime']!==$runtime||$current['generation']!==$generation)throw new RuntimeException('Bootstrap worker was superseded.');
    }
}
