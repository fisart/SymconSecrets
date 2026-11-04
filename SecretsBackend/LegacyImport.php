<?php
declare(strict_types=1);
require_once __DIR__.'/Tree.php';
require_once __DIR__.'/NativePlatform.php';

/** Explicit administrator import of retained aes-128-gcm snapshots. Never used by SEC application calls. */
final class SecretsBackendLegacyImport
{
    public const MODULE='{7C5A3841-3F7B-4D2A-9E1C-5B6D8F9A0E12}';
    public static function sources(): array
    {
        $out=[];foreach(IPS_GetInstanceListByModuleID(self::MODULE)as$id){$id=(int)$id;$out[]=['id'=>$id,'name'=>IPS_GetName($id),'ready'=>(IPS_GetInstance($id)['InstanceStatus']??0)===102&&!IPS_HasChanges($id)];}return $out;
    }
    public static function read(int $id,int $limit): array { return self::withSnapshot($id,$limit,static fn($snapshot)=>$snapshot); }
    public static function withSnapshot(int $id,int $limit,callable $callback)
    {
        if($id<=0||!IPS_InstanceExists($id)||strtoupper(IPS_GetInstance($id)['ModuleInfo']['ModuleID']??'')!==self::MODULE||IPS_HasChanges($id)||(IPS_GetInstance($id)['InstanceStatus']??0)!==102)throw new RuntimeException('Select a ready retained vault instance without pending console edits.');
        $lock='SymconSecrets.Vault.'.$id;if(!IPS_SemaphoreEnter($lock,5000))throw new RuntimeException('The old vault is busy. Try again.');
        try{
            $raw=IPS_GetConfiguration($id);if(!is_string($raw)||strlen($raw)>65536)throw new RuntimeException('Unsupported old configuration.');
            $config=SecretsFrontendConfiguration::decode($raw);$folder=$config['KeyFolderPath']??'';
            if(!is_string($folder)||$folder==='')throw new RuntimeException('The old key folder is not configured.');
            $folder=SecretsBackendNativePlatform::directory($folder);$file=$folder.'/master.key';
            if(is_link($file)||!is_file($file)||filesize($file)>256)throw new RuntimeException('The existing legacy master.key is unavailable. No key was created.');
            $key=trim((string)file_get_contents($file));if(!preg_match('/^[a-fA-F0-9]{32}$/D',$key))throw new RuntimeException('The old key has an unsupported format.');
            $variable=IPS_GetObjectIDByIdent('Vault',$id);$cipher=GetValueString($variable);
            if($cipher===''||strlen($cipher)>min(1048576,$limit*2))throw new RuntimeException('The old vault is empty or exceeds this import memory budget.');
            $metadata=self::configuration($id,$config,$folder);
            $snapshot=self::decode($cipher,$key,$limit);
            $snapshot['source']=$metadata;
            $snapshot['fingerprint']=hash('sha256',$cipher."\0".hash('sha256',$key)."\0".$raw);
            return $callback($snapshot);
        }finally{IPS_SemaphoreLeave($lock);}
    }
    public static function decode(string $cipher,string $key,int $limit): array
    {
        $envelope=SecretsFrontendConfiguration::decodeBounded($cipher,min(1048576,$limit*2),8);
        if(($envelope['cipher']??'')!=='aes-128-gcm'||!is_string($envelope['data']??null)||!is_string($envelope['iv']??null)||!is_string($envelope['tag']??null)||!preg_match('/^[a-fA-F0-9]{24}$/D',$envelope['iv'])||!preg_match('/^[a-fA-F0-9]{32}$/D',$envelope['tag'])||!preg_match('/^[a-fA-F0-9]{32}$/D',$key))throw new RuntimeException('Unsupported old vault encryption.');
        $plain=openssl_decrypt($envelope['data'],'aes-128-gcm',hex2bin($key),0,hex2bin($envelope['iv']),hex2bin($envelope['tag']));
        if(!is_string($plain)||strlen($plain)>$limit)throw new RuntimeException('Old vault authentication failed or data exceeds the import budget.');
        SecretsFrontendConfiguration::decodeBounded('{"vault":'.$plain.'}',$limit+16,20);
        $root=json_decode($plain,false,20,JSON_THROW_ON_ERROR);
        if(is_array($root)&&$root===[])$root=new stdClass();
        if(!is_object($root))throw new RuntimeException('The old vault root must be an object.');
        $local=$root->__LOCAL__??new stdClass();if(is_array($local)&&$local===[])$local=new stdClass();
        if(!is_object($local))throw new RuntimeException('The old local-secret area is not a folder.');
        $excluded=[];foreach(array_keys(get_object_vars($root))as$name)if(str_starts_with((string)$name,'__')){if($name!=='__LOCAL__')$excluded[]=(string)$name;unset($root->{$name});}
        $clean=static function($node)use(&$clean){if(is_object($node)){if(isset($node->__folder)&&$node->__folder===true)unset($node->__folder);foreach(get_object_vars($node)as$key=>$value)$node->{$key}=$clean($value);}elseif(is_array($node))$node=array_map($clean,$node);return $node;};
        $globalNode=SecretsBackendTree::parseBounded(SecretsBackendCodec::json($clean($root)),$limit);
        $localNode=SecretsBackendTree::parseBounded(SecretsBackendCodec::json($clean($local)),$limit);
        return ['global'=>$globalNode,'local'=>$localNode,'excluded'=>$excluded];
    }
    private static function configuration(int $id,array $c,string $folder): array
    {
        $connections=[];$warnings=[];$rows=json_decode((string)($c['SlaveURLs']??'[]'),true,12,JSON_THROW_ON_ERROR);
        if(!is_array($rows)||count($rows)>64)throw new RuntimeException('Unsupported old connection configuration.');
        foreach($rows as$row){
            if(!is_array($row))throw new RuntimeException('Invalid old connection row.');
            $url=(string)($row['Url']??'');$parts=parse_url($url);
            // Only known hook locators are carried over; credentials/query are never imported.
            $safe=is_array($parts)&&in_array($parts['scheme']??'', ['http','https'],true)&&isset($parts['host'])&&preg_match('~^/hook/secrets_[1-9][0-9]*/?$~D',$parts['path']??'');
            if(!$safe){$warnings[]='A connection with an unsupported URL needs manual review.';continue;}
            $host=$parts['host'];if(!preg_match('/^[a-zA-Z0-9.-]+$/D',$host)){$warnings[]='A connection hostname needs manual review.';continue;}
            $target=$parts['scheme'].'://'.strtolower($host).(isset($parts['port'])?':'.$parts['port']:'').$parts['path'];
            $label=(string)($row['Server']??'Remote vault');if(strlen($label)>160||preg_match('/[\x00-\x1f\x7f]/',$label))$label='Remote vault';
            $fingerprint=(string)($row['Fingerprint']??'');if(!preg_match('/^(?:[a-fA-F0-9]{2}:?){32}$/D',$fingerprint))$fingerprint='';
            $connections[]=['name'=>$label,'legacyEndpoint'=>$target,'legacyCertificateFingerprint'=>$fingerprint,'legacyKeyTransport'=>in_array($row['KeyTransport']??'', ['manual','sync'],true)?$row['KeyTransport']:'unreviewed','tlsMode'=>in_array($row['TlsMode']??'', ['http','strict','pinned'],true)?$row['TlsMode']:'unreviewed','state'=>'needs-new-pairing'];
            if(isset($parts['user'])||isset($parts['pass'])||isset($parts['query'])||isset($parts['fragment']))$warnings[]='Credentials or query parameters were removed from a legacy connection.';
        }
        $mode=$c['OperationMode']??null;if(!is_int($mode)||!in_array($mode,[0,1,2],true))throw new RuntimeException('Unsupported old vault role.');
        return ['id'=>$id,'name'=>IPS_GetName($id),'role'=>['receiver','sender','standalone'][$mode],
            'legacyVaultLocation'=>'Symcon instance '.$id.' / Encrypted Vault variable','legacyKeyFolder'=>$folder,'legacySystemVaultPath'=>$folder.'/system.vault',
            'suggestedVaultDirectory'=>$folder.'/secrets-native-data-'.$id,'suggestedKeyDirectory'=>$folder.'/secrets-native-keys-'.$id,
            'connections'=>$connections,'warnings'=>$warnings];
    }
    public static function merge(array $target,array $incoming,string $policy,array &$stats,array $path=[]): array
    {
        if($target['type']==='object'&&$incoming['type']==='object'){
            foreach($incoming['entries']as$entry){$found=null;foreach($target['entries']as$i=>$old)if($old['key']===$entry['key']){$found=$i;break;}
                if($found===null){$target['entries'][]=$entry;$stats['added']++;}
                else $target['entries'][$found]['node']=self::merge($target['entries'][$found]['node'],$entry['node'],$policy,$stats,array_merge($path,[$entry['key']]));
            }
            if(count($target['entries'])>200)throw new RuntimeException('Imported folder exceeds 200 children.');return $target;
        }
        if(SecretsBackendNativeStore::canonical($target)===SecretsBackendNativeStore::canonical($incoming)){$stats['unchanged']++;return $target;}
        if(count($stats['conflicts'])>=200)throw new RuntimeException('More than 200 conflicts; split the migration before importing.');
        $stats['conflicts'][]=$path;if($policy==='replace'){$stats['replaced']++;return $incoming;}$stats['kept']++;return $target;
    }
    public static function plan(array $state,array $source,string $policy,int $limit,string $importScope='all'): array
    {
        if(!in_array($policy,['keep','replace'],true))throw new RuntimeException('Choose how to handle existing values.');
        if(!in_array($importScope,['all','local'],true))throw new RuntimeException('Choose Local secrets only or Global and Local secrets.');
        $trees=[];$stats=[];foreach(['global','local']as$scope){
            $stats[$scope]=['added'=>0,'replaced'=>0,'kept'=>0,'unchanged'=>0,'conflicts'=>[],'skipped'=>$importScope==='local'&&$scope==='global'];
            // Preserve the exact Global tree, including conflicted native versions, without merging old Global data.
            if($stats[$scope]['skipped']){$trees[$scope]=$state['vault'][$scope];continue;}
            $trees[$scope]=self::merge($state['vault'][$scope],$source[$scope],$policy,$stats[$scope]);
            // Enforce the native limits on the complete merged hierarchy before approval.
            SecretsBackendTree::parseBounded(SecretsBackendCodec::json(SecretsBackendTree::value($trees[$scope])),$limit);
        }
        return ['trees'=>$trees,'summary'=>$stats,'scope'=>$importScope];
    }
}
