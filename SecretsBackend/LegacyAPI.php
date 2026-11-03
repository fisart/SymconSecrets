<?php
declare(strict_types=1);
require_once __DIR__.'/NativeStore.php';
require_once __DIR__.'/NativePeer.php';

/** Application-data compatibility only. Identity material never enters the legacy data view. */
final class SecretsBackendLegacyAPI
{
    public const REVIEW_FIELDS=['kind','instance','mode','enabled','read','write','portal','frozen','bulk'];
    public const DATA_METHODS=['GetKeys','GetSecret','GetExplorerFields','SetRecordFields','ExportLocalSecrets','ImportLocalSecrets','EncryptAndSave'];
    public function __construct(private SecretsBackendNativeStore $store,private int $instance,private $binding,private int $backend=0) {}
    private string $output='';
    public function output(): string {return $this->output;}
    public static function review(array $op): array
    {
        SecretsBackendNativePeer::exact($op,self::REVIEW_FIELDS);
        if($op['kind']!=='nativeLegacyAccess'||!is_int($op['instance'])||$op['instance']<=0||!is_int($op['mode'])||!in_array($op['mode'],[0,1,2],true))throw new InvalidArgumentException('Choose an exact legacy instance and its existing operation mode.');
        foreach(['enabled','read','write','portal','frozen','bulk']as$key)if(!is_bool($op[$key]))throw new InvalidArgumentException('Choose explicit legacy access permissions.');
        return $op;
    }
    /** Trusted local PHP reads work by default only on this native backend itself. */
    public static function access(array $state,int $instance,int $backend): ?array
    {
        $grants=$state['native']['legacyAccess']??[];
        if(array_key_exists((string)$instance,$grants))return is_array($grants[(string)$instance])?$grants[(string)$instance]:null;
        if($backend<=0||$instance!==$backend)return null;
        return ['kind'=>'nativeLegacyAccess','instance'=>$backend,'mode'=>2,'enabled'=>true,'read'=>true,'write'=>false,'portal'=>false,'frozen'=>true,'bulk'=>false,'treeId'=>$state['native']['globalTreeId'],'defaultReadAccess'=>true];
    }
    public function permission(array $state,string $right,bool $write=false): array
    {
        $p=self::access($state,$this->instance,$this->backend);
        if(!is_array($p)||($p['treeId']??'')!==$state['native']['globalTreeId']||!$p['enabled']||!($p[$right]??false)||($write&&$p['frozen']))throw new RuntimeException('Legacy application access is disabled, unapproved or frozen.');
        ($this->binding)($p);return $p;
    }
    private function snapshot(): array { $c=$this->store->read();$this->permission($c['state'],'read');return $c; }
    private function read(callable $get,string $method)
    {
        $c=$this->snapshot();
        $this->store->authorize('legacy-read',hash('sha256',$method.':'.$this->instance),$c,function(array $checked):void{$this->permission($checked['state'],'read');},['action'=>'legacy-read','actor'=>(string)$this->instance,'target'=>$method]);
        return $get($c['state']);
    }
    private static function value(array $node)
    {
        // Old json_decode(..., true) collapses empty objects to [] and keeps numeric keys.
        return self::normalizeFolders(json_decode(SecretsBackendCodec::json(SecretsBackendTree::value($node)),true,32,JSON_THROW_ON_ERROR));
    }
    private static function normalizeFolders($value)
    {
        if(!is_array($value))return $value;
        $folder=false;foreach($value as&$child)if(is_array($child)){$folder=true;$child=self::normalizeFolders($child);}unset($child);
        if($folder||!$value)$value['__folder']=true;return $value;
    }
    private static function cleanFolders($value)
    {
        if(is_array($value)){if(($value['__folder']??false)===true)unset($value['__folder']);foreach($value as&$child)$child=self::cleanFolders($child);unset($child);}return $value;
    }
    private static function encoded($v): string { return is_array($v)||is_object($v)?(str_replace(['"__folder":true,',',"__folder":true','"__folder":true'], '',json_encode($v))?:''):(string)$v; }
    public function GetKeys(): string
    {
        return $this->read(static function(array $s):string{
            $root=self::value(isset($s['native']['sharedGlobal'])?SecretsBackendSharedGlobal::available($s):$s['vault']['global']);
            return json_encode(array_values(array_filter(array_keys($root),static fn($k)=>!str_starts_with((string)$k,'__'))),JSON_THROW_ON_ERROR);
        },__FUNCTION__);
    }
    public function GetSecret(string $ident): string
    {
        return $this->read(static function(array $s)use($ident):string{
            if($ident==='__LOCAL__')return self::encoded(self::value($s['vault']['local']));
            if(str_starts_with($ident,'__'))throw new RuntimeException('Legacy identity/internal areas are unavailable through the application API.');
            if(isset($s['native']['sharedGlobal']))SecretsBackendSharedGlobal::assertPath($s,[$ident],false);
            $root=self::value($s['vault']['global']);if(!array_key_exists($ident,$root))throw new RuntimeException('Application record is unavailable.',2101);
            return self::encoded($root[$ident]);
        },__FUNCTION__);
    }
    public function GetExplorerFields(string $ident): array
    {
        return $this->read(static function(array $s)use($ident):array{
            $parts=explode('/',$ident);if(in_array('',$parts,true))return [];
            if($parts[0]==='__LOCAL__'){$node=self::value($s['vault']['local']);array_shift($parts);}
            else {if(str_starts_with($parts[0],'__'))throw new RuntimeException('Legacy identity/internal areas are unavailable.');if(isset($s['native']['sharedGlobal']))SecretsBackendSharedGlobal::assertPath($s,$parts,false);$node=self::value($s['vault']['global']);}
            foreach($parts as$p){if(!is_array($node)||!array_key_exists($p,$node))return [];$node=$node[$p];}
            $out=[];if(is_array($node))foreach($node as$k=>$v)if(!is_array($v)&&$k!=='__folder')$out[]=['Key'=>$k,'Value'=>(string)$v];return $out;
        },__FUNCTION__);
    }
    public function ExportLocalSecrets(): string
    {
        return $this->read(static fn(array $s):string=>json_encode(['__LOCAL__'=>self::value($s['vault']['local'])],JSON_PRETTY_PRINT|JSON_THROW_ON_ERROR),__FUNCTION__);
    }
    private function write(string $method,array $args,callable $mutate): bool
    {
        $current=$this->store->read();$this->permission($current['state'],'write',true);
        $this->store->change($current['head'],SecretsBackendCodec::uuid(),hash('sha256',SecretsBackendCodec::json([$this->instance,$method,$args])),function(array $s)use($mutate):array{
            $p=$this->permission($s,'write',true);$before=$s['vault'];$s=$mutate($s,$p);
            foreach(['global','local']as$scope)SecretsBackendTree::parseBounded(SecretsBackendCodec::json(SecretsBackendTree::value($s['vault'][$scope])),$this->store->metadata()['capacityBytes']);
            if(SecretsBackendNativeStore::canonical($before)!==SecretsBackendNativeStore::canonical($s['vault'])){
                $s['vault']['revision']=SecretsBackendCodec::increment($s['vault']['revision']);
                if(SecretsBackendNativeStore::canonical($before['global'])!==SecretsBackendNativeStore::canonical($s['vault']['global'])){$s['stream']['globalRevision']=SecretsBackendCodec::increment($s['stream']['globalRevision']);$s=SecretsBackendNativePeer::queueGlobal($s);}
            }return $s;
        },['action'=>'legacy-write','actor'=>(string)$this->instance,'target'=>$method]);return true;
    }
    public function SetRecordFields(string $path,array $fields,string $scope): bool
    {
        $scope=strtolower(trim($scope));$path=trim($path);
        if(!in_array($scope,['global','local'],true)||$path===''||$path[0]==='/'||str_ends_with($path,'/'))return false;
        $parts=array_map('trim',explode('/',$path));if(in_array('',$parts,true))return false;
        $normalized=[];foreach($fields as$k=>$v){$k=trim((string)$k);if($k===''||str_starts_with($k,'__')||is_array($v)||is_object($v))return false;$normalized[$k]=(string)$v;}
        SecretsBackendTree::path($parts);
        $native=$this->instance===$this->backend;
        return $this->write(__FUNCTION__,[$path,$normalized,$scope],static function(array $s,array $permission)use($parts,$normalized,$scope,$native):array{
            if($scope==='global'&&((!$native&&$permission['mode']!==1)||!$s['native']['globalWritable']))throw new RuntimeException('Global writes require legacy Master mode and a writable Global vault.');
            if($scope==='global'&&isset($s['native']['sharedGlobal']))SecretsBackendSharedGlobal::assertPath($s,$parts,false);
            self::setFields($s['vault'][$scope],$parts,$normalized);return $s;
        });
    }
    public function EncryptAndSave(string $jsonInput): void
    {
        $p=$this->permission($this->store->read()['state'],'write',true);
        if($this->instance!==$this->backend&&$p['mode']===0){$this->output='Operation not allowed in Slave mode.';return;}
        if(!$p['bulk'])throw new RuntimeException('Whole-vault application replacement requires explicit bulk-write approval.');
        if(trim($jsonInput)===''){$this->output='Input empty.';return;}
        if(strlen($jsonInput)>SecretsBackendNativePlatform::budget())throw new RuntimeException('Legacy input exceeds the native budget.');
        $decoded=json_decode($jsonInput,true,32);
        if(!is_array($decoded)){$this->output='❌ JSON Syntax Error!';return;}
        foreach(array_keys($decoded)as$key)if(str_starts_with((string)$key,'__')&&!in_array($key,['__LOCAL__','__folder'],true))throw new RuntimeException('Legacy internal/credential replacement is unavailable.');
        if(isset($decoded['__LOCAL__'])&&!is_array($decoded['__LOCAL__']))throw new RuntimeException('Local application secrets must be a folder.');
        $local=self::cleanFolders($decoded['__LOCAL__']??[]);unset($decoded['__LOCAL__']);$global=self::cleanFolders($decoded);
        $global=SecretsBackendTree::parseBounded(json_encode($global?:new stdClass(),JSON_THROW_ON_ERROR),SecretsBackendNativePlatform::budget());
        $local=SecretsBackendTree::parseBounded(json_encode($local?:new stdClass(),JSON_THROW_ON_ERROR),SecretsBackendNativePlatform::budget());
        $native=$this->instance===$this->backend;
        $this->write(__FUNCTION__,[$jsonInput],static function(array $s,array $p)use($global,$local,$native):array{
            if(!$p['bulk']||(!$native&&$p['mode']===0)||!$s['native']['globalWritable'])throw new RuntimeException('Whole-vault write is unapproved or Global is frozen.');
            if(isset($s['native']['sharedGlobal']))SecretsBackendSharedGlobal::assertPath($s,[],false);
            $s['vault']['global']=$global;$s['vault']['local']=$local;return $s;
        });$this->output='✅ Saved & Encrypted locally.';
    }
    private static function objectNode(array $node): array
    {
        if($node['type']==='object')return $node;
        $entries=[];if($node['type']==='array')foreach($node['items']as$i=>$item)$entries[]=['key'=>(string)$i,'node'=>$item];
        return ['type'=>'object','entries'=>$entries];
    }
    private static function setFields(array &$node,array $parts,array $fields): void
    {
        if(!$parts){
            $node=self::objectNode($node);
            $node['entries']=array_values(array_filter($node['entries'],static fn($entry)=>in_array($entry['node']['type'],['object','array'],true)));
            foreach($fields as$key=>$value){$found=false;foreach($node['entries']as&$entry)if($entry['key']===(string)$key){$entry['node']=['type'=>'string','value'=>$value];$found=true;break;}unset($entry);if(!$found)$node['entries'][]=['key'=>(string)$key,'node'=>['type'=>'string','value'=>$value]];}
            return;
        }
        $part=array_shift($parts);
        if($node['type']==='array'&&preg_match('/^[0-9]+$/D',$part)&&(string)(int)$part===$part&&isset($node['items'][(int)$part])){self::setFields($node['items'][(int)$part],$parts,$fields);return;}
        $node=self::objectNode($node);
        foreach($node['entries']as&$entry)if($entry['key']===$part){self::setFields($entry['node'],$parts,$fields);return;}unset($entry);
        $child=['type'=>'object','entries'=>[]];self::setFields($child,$parts,$fields);$node['entries'][]=['key'=>$part,'node'=>$child];
    }
    public function ImportLocalSecrets(string $json): bool
    {
        if(strlen($json)>SecretsBackendNativePlatform::budget())return false;
        $data=json_decode($json,true,32);if(!is_array($data))return false;
        // Credential injection/export is deliberately not emulated. Reject atomically.
        if(array_key_exists('__AUTH__',$data))throw new RuntimeException('Passkeys must use the new approved enrollment workflow; no legacy identity was imported.');
        if(isset($data['__LOCAL__'])&&!is_array($data['__LOCAL__']))return false;
        return $this->write(__FUNCTION__,[$data],static function(array $s)use($data):array{
            if(isset($data['__LOCAL__']))$s['vault']['local']=SecretsBackendTree::parseBounded(json_encode(self::cleanFolders($data['__LOCAL__'])?:new stdClass(),JSON_THROW_ON_ERROR),SecretsBackendNativePlatform::budget());return $s;
        });
    }
}
