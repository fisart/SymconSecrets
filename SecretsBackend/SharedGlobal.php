<?php
declare(strict_types=1);
require_once __DIR__.'/Tree.php';

/** Observed-remove multi-value registers. Wall clocks never select a secret. */
final class SecretsBackendSharedGlobal
{
    public const SCOPE='shared-global-v1';
    private static function key(array $path): string { return SecretsBackendCodec::b64(SecretsBackendCodec::json($path)); }
    private static function hash($v): string { return hash('sha256',SecretsBackendNativeStore::canonical($v)); }
    private static function cmp(string $a,string $b): int { return strlen($a)<=>strlen($b) ?: strcmp($a,$b); }
    private static function prefix(array $a,array $b): bool { return array_slice($b,0,count($a))===$a; }
    private static function normalizeNode(array $node): array
    {
        if($node['type']==='object'){foreach($node['entries']as&$e)$e['node']=self::normalizeNode($e['node']);unset($e);usort($node['entries'],static fn($a,$b)=>strcmp($a['key'],$b['key']));}
        elseif($node['type']==='array')$node['items']=array_map([self::class,'normalizeNode'],$node['items']);
        return $node;
    }
    private static function flatten(array $node,array $path=[],array &$out=[]): array
    {
        if($path)$out[self::key($path)]=['path'=>$path,'node'=>$node['type']==='object'?['type'=>'object','entries'=>[]]:self::normalizeNode($node)];
        if($node['type']==='object')foreach($node['entries']as$e)self::flatten($e['node'],[...$path,$e['key']],$out);
        return $out;
    }
    public static function empty(): array { return ['format'=>'SECB.SharedGlobal.1','clock'=>[],'records'=>[]]; }
    public static function validate(array $m): void
    {
        if(array_keys($m)!==['format','clock','records']&&array_diff(array_keys($m),['format','clock','records']))throw new RuntimeException('Unexpected shared Global fields.');
        if(($m['format']??'')!=='SECB.SharedGlobal.1'||!is_array($m['clock']??null)||!is_array($m['records']??null)||count($m['clock'])>64||count($m['records'])>5000)throw new RuntimeException('Unsupported or oversized shared Global state.');
        foreach($m['clock']as$id=>$counter){if(!is_string($id)||!preg_match('/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/D',$id)||!is_string($counter)||!preg_match('/^[1-9][0-9]{0,17}$/D',$counter))throw new RuntimeException('Invalid Global version clock.');}
        foreach($m['records']as$key=>$r){
            if(!is_array($r)||array_diff(array_keys($r),['path','versions'])||!is_array($r['path']??null)||!$r['path']||!is_array($r['versions']??null)||!$r['versions']||count($r['versions'])>64)throw new RuntimeException('Invalid Global register.');
            SecretsBackendTree::path($r['path']);foreach($r['path']as$p)if(!is_string($p))throw new RuntimeException('Lists are atomic Global values.');
            if($key!==self::key($r['path']))throw new RuntimeException('Global path binding failed.');
            foreach($r['versions']as$id=>$v){
                if(!is_array($v)||array_diff(array_keys($v),['counter','node'])||!isset($m['clock'][$id],$v['counter'])||!array_key_exists('node',$v)||!is_string($v['counter'])||!preg_match('/^[1-9][0-9]{0,17}$/D',$v['counter'])||self::cmp($v['counter'],$m['clock'][$id])>0)throw new RuntimeException('Invalid Global version.');
                if($v['node']!==null){if(!is_array($v['node']))throw new RuntimeException('Invalid Global value.');$n=self::normalizeNode(SecretsBackendTree::parseBounded(SecretsBackendCodec::json(SecretsBackendTree::value($v['node'])),524288));if(self::hash($n)!==self::hash($v['node'])||($n['type']==='object'&&$n['entries']))throw new RuntimeException('Invalid Global typed value.');}
            }
        }
    }
    public static function join(array $a,array $b): array
    {
        self::validate($a);self::validate($b);$out=self::empty();
        foreach(array_unique([...array_keys($a['clock']),...array_keys($b['clock'])])as$id)$out['clock'][$id]=self::cmp($a['clock'][$id]??'0',$b['clock'][$id]??'0')>=0?($a['clock'][$id]??'0'):$b['clock'][$id];
        foreach(array_unique([...array_keys($a['records']),...array_keys($b['records'])])as$key){
            $x=$a['records'][$key]??null;$y=$b['records'][$key]??null;$versions=[];
            foreach([[$x,$y,$b['clock']],[$y,$x,$a['clock']]]as[$left,$right,$clock])foreach($left['versions']??[]as$id=>$v){
                $other=$right['versions'][$id]??null;
                if($other!==null&&$other['counter']===$v['counter']){if(self::hash($other)!==self::hash($v))throw new RuntimeException('A Global version has conflicting contents.');$versions[$id]=$v;}
                elseif(self::cmp($v['counter'],$clock[$id]??'0')>0)$versions[$id]=$v;
            }
            if($versions){ksort($versions,SORT_STRING);$out['records'][$key]=['path'=>($x??$y)['path'],'versions'=>$versions];}
        }
        ksort($out['clock'],SORT_STRING);ksort($out['records'],SORT_STRING);self::validate($out);return $out;
    }
    /** Deterministic display projection; conflicted paths MUST NOT be read or edited normally. */
    public static function view(array $m): array
    {
        $children=[];foreach($m['records']as$r){$p=$r['path'];$name=array_pop($p);$children[self::key($p)][$name]=true;}
        $conflicts=[];
        $build=function(array $path)use(&$build,&$conflicts,$children,$m):?array{
            $key=self::key($path);$entries=[];$names=array_keys($children[$key]??[]);sort($names,SORT_STRING);
            foreach($names as$name){$child=$build([...$path,(string)$name]);if($child!==null)$entries[]=['key'=>(string)$name,'node'=>$child];}
            if(count($entries)>200)throw new RuntimeException('Merged Global folder exceeds 200 entries. Split it into folders before sharing.');
            if(!$path)return ['type'=>'object','entries'=>$entries];
            $candidates=[];foreach($m['records'][$key]['versions']??[]as$id=>$v){$node=$v['node'];if(($node['type']??'')==='object')$node=['type'=>'object','entries'=>$entries];$hash=self::hash($node);if(!isset($candidates[$hash]))$candidates[$hash]=['id'=>$hash,'node'=>$node,'platforms'=>[]];$candidates[$hash]['platforms'][]=$id;}
            // A concurrent child creation survives deletion/replacement of its parent.
            if($entries&&!array_filter($candidates,static fn($c)=>($c['node']['type']??'')==='object')){$node=['type'=>'object','entries'=>$entries];$hash=self::hash($node);$candidates[$hash]=['id'=>$hash,'node'=>$node,'platforms'=>[]];}
            $provenance=$m['clock'];
            foreach($candidates as&$c){sort($c['platforms'],SORT_STRING);$c['id']=self::hash([$path,$c['platforms'],$c['node']['type']??'deleted',$provenance]);}unset($c);
            usort($candidates,static fn($a,$b)=>strcmp($a['id'],$b['id']));
            // Public identifiers bind causal versions, never hashes of guessable secret values.
            if(count($candidates)>1)$conflicts[$key]=['path'=>$path,'digest'=>self::hash(array_column($candidates,'id')),'versions'=>array_values($candidates)];
            // Prefer an object for navigation; reads of any conflicting subtree are fenced.
            foreach($candidates as$c)if(($c['node']['type']??'')==='object')return $c['node'];
            foreach($candidates as$c)if($c['node']!==null)return $c['node'];return null;
        };
        $node=$build([]);ksort($conflicts,SORT_STRING);return ['node'=>$node,'conflicts'=>array_values($conflicts)];
    }
    public static function assertPath(array $state,array $path,bool $read=false): void
    {
        if(!isset($state['native']['sharedGlobal']))return;
        foreach(self::view($state['native']['sharedGlobal'])['conflicts']as$c)if((!$read&&self::prefix($path,$c['path']))||self::prefix($c['path'],$path))throw new RuntimeException('Global secret has unresolved versions. Open Secrets and select Resolve conflict.');
    }
    public static function available(array $state): array
    {
        $node=$state['vault']['global'];if(!isset($state['native']['sharedGlobal']))return $node;
        // Conflicting versions stay in the encrypted model and the Conflicts tab only.
        foreach(self::view($state['native']['sharedGlobal'])['conflicts']as$c){try{SecretsBackendTree::edit($node,$c['path'],null,'delete');}catch(InvalidArgumentException $ignored){}}
        return $node;
    }
    private static function write(array $m,string $author,array $changes): array
    {
        if(!$changes)return $m;$counter=SecretsBackendCodec::increment($m['clock'][$author]??'0');$m['clock'][$author]=$counter;
        foreach($changes as$key=>$entry)$m['records'][$key]=['path'=>$entry['path'],'versions'=>[$author=>['counter'=>$counter,'node'=>$entry['node']]]];
        ksort($m['clock'],SORT_STRING);ksort($m['records'],SORT_STRING);self::validate($m);return $m;
    }
    public static function enable(array $s): array
    {
        if(isset($s['native']['sharedGlobal']))return $s;
        if(!$s['native']['globalWritable']||$s['native']['trees'])throw new RuntimeException('Resolve ownership transfers before joining one shared Global vault.');
        $s['native']['sharedGlobal']=self::write(self::empty(),$s['native']['vaultId'],self::flatten($s['vault']['global']));
        $s['vault']['global']=self::view($s['native']['sharedGlobal'])['node'];
        $s['vault']['revision']=SecretsBackendCodec::increment($s['vault']['revision']);$s['stream']['globalRevision']=SecretsBackendCodec::increment($s['stream']['globalRevision']);
        return $s;
    }
    public static function capture(array $s): array
    {
        if(!isset($s['native']['sharedGlobal']))return $s;
        $before=self::flatten(self::view($s['native']['sharedGlobal'])['node']);$after=self::flatten($s['vault']['global']);$changes=[];
        foreach(array_unique([...array_keys($before),...array_keys($after)])as$key){$a=$before[$key]['node']??null;$b=$after[$key]['node']??null;if(self::hash($a)===self::hash($b))continue;$path=($after[$key]??$before[$key])['path'];self::assertPath($s,$path);$changes[$key]=['path'=>$path,'node'=>$b];}
        $s['native']['sharedGlobal']=self::write($s['native']['sharedGlobal'],$s['native']['vaultId'],$changes);
        $s['vault']['global']=self::view($s['native']['sharedGlobal'])['node'];return $s;
    }
    public static function receive(array $s,array $model): array
    {
        $s=self::enable($s);$merged=self::join($s['native']['sharedGlobal'],$model);
        if(self::hash($merged)===self::hash($s['native']['sharedGlobal']))return $s;
        $s['native']['sharedGlobal']=$merged;$s['vault']['global']=self::view($merged)['node'];
        $s['vault']['revision']=SecretsBackendCodec::increment($s['vault']['revision']);$s['stream']['globalRevision']=SecretsBackendCodec::increment($s['stream']['globalRevision']);return $s;
    }
    public static function conflict(array $s,array $path,string $digest): array
    {
        foreach(self::view($s['native']['sharedGlobal']??self::empty())['conflicts']as$c)if($c['path']===$path&&hash_equals($c['digest'],$digest))return $c;
        throw new RuntimeException('The conflict changed. Refresh and review its current versions.');
    }
    /** Each choice keeps one version under an explicit sibling name; omitted versions are discarded by approval. */
    public static function resolve(array $s,array $path,string $digest,array $choices): array
    {
        $c=self::conflict($s,$path,$digest);$m=$s['native']['sharedGlobal'];$view=self::view($m);
        foreach($view['conflicts']as$other)if($other['path']!==$path&&self::prefix($path,$other['path']))throw new RuntimeException('Resolve conflicts inside this folder first.');
        if(!$choices||array_values($choices)!==$choices||count($choices)>count($c['versions']))throw new RuntimeException('Choose the versions to keep.');
        $parent=$path;array_pop($parent);$changes=[];$seen=[];$ids=[];
        foreach($m['records']as$key=>$r)if(self::prefix($path,$r['path']))$changes[$key]=['path'=>$r['path'],'node'=>null];
        foreach($choices as$choice){
            if(!is_array($choice)||array_diff(array_keys($choice),['id','name'])||!is_string($choice['id']??null)||!is_string($choice['name']??null))throw new RuntimeException('Choose a version and its name.');
            $target=[...$parent,$choice['name']];SecretsBackendTree::path($target);$key=self::key($target);if(isset($seen[$key])||isset($ids[$choice['id']]))throw new RuntimeException('Use a different name for each version.');$seen[$key]=true;$ids[$choice['id']]=true;
            $candidate=null;foreach($c['versions']as$v)if($v['id']===$choice['id'])$candidate=$v;if($candidate===null)throw new RuntimeException('Unknown conflict version.');
            if($target!==$path){self::assertPath($s,$target);$exists=false;try{SecretsBackendTree::at($view['node'],$target);$exists=true;}catch(InvalidArgumentException $ignored){}if($exists)throw new RuntimeException('That name already exists; choose a new name.');}
            if($candidate['node']!==null)foreach(self::flatten($candidate['node'],$target)as$k=>$entry)$changes[$k]=$entry;
        }
        $s['native']['sharedGlobal']=self::write($m,$s['native']['vaultId'],$changes);$s['vault']['global']=self::view($s['native']['sharedGlobal'])['node'];$s['vault']['revision']=SecretsBackendCodec::increment($s['vault']['revision']);$s['stream']['globalRevision']=SecretsBackendCodec::increment($s['stream']['globalRevision']);return $s;
    }
    public static function metadata(array $s): ?array
    {
        if(!isset($s['native']['sharedGlobal']))return null;
        $conflicts=[];foreach(self::view($s['native']['sharedGlobal'])['conflicts']as$c){foreach($c['versions']as&$v){$v['type']=$v['node']['type']??'deleted';unset($v['node']);}unset($v);$conflicts[]=$c;}
        return ['mode'=>self::SCOPE,'conflicts'=>$conflicts,'policy'=>'preserve-concurrent-versions'];
    }
}
