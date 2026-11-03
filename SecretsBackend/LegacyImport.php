<?php
declare(strict_types=1);
require_once __DIR__.'/Tree.php';
require_once __DIR__.'/NativePlatform.php';

/** Read-only adapter for the deployed aes-128-gcm legacy format. No old APIs execute. */
final class SecretsBackendLegacyImport
{
    public const MODULE='{7C5A3841-3F7B-4D2A-9E1C-5B6D8F9A0E12}';
    public static function sources(): array { return []; }
    public static function read(int $id,int $limit): array { throw new RuntimeException('Old vault access is disabled on the native-only replacement branch.'); }
    public static function withSnapshot(int $id,int $limit,callable $callback) { throw new RuntimeException('Old vault access is disabled on the native-only replacement branch.'); }
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
    public static function plan(array $state,array $source,string $policy,int $limit): array
    {
        if(!in_array($policy,['keep','replace'],true))throw new RuntimeException('Choose how to handle existing values.');
        $trees=[];$stats=[];foreach(['global','local']as$scope){$stats[$scope]=['added'=>0,'replaced'=>0,'kept'=>0,'unchanged'=>0,'conflicts'=>[]];$trees[$scope]=self::merge($state['vault'][$scope],$source[$scope],$policy,$stats[$scope]);
            // Enforce the native limits on the complete merged hierarchy before approval.
            SecretsBackendTree::parseBounded(SecretsBackendCodec::json(SecretsBackendTree::value($trees[$scope])),$limit);
        }
        return ['trees'=>$trees,'summary'=>$stats];
    }
}
