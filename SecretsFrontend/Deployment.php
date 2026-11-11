<?php
declare(strict_types=1);
require_once __DIR__.'/Configuration.php';

/** Proposed placement only. Never a trust pack, admission or activation record. */
final class SecretsFrontendDeployment
{
    public static function defaults(string $origin): array
    {
        return ['authorities'=>array_map(static fn($n)=>['name'=>'Authority '.$n,'endpoint'=>'','failureDomain'=>''],[1,2,3]),
            'peers'=>[['name'=>'This Symcon installation','origin'=>$origin,'failureDomain'=>''],['name'=>'Second Symcon installation','origin'=>'','failureDomain'=>'']],
            'recoveryLocations'=>['','']];
    }
    private static function fields(array $v,array $keys): void
    {
        if(array_diff(array_keys($v),$keys)||array_diff($keys,array_keys($v)))throw new InvalidArgumentException('Unexpected deployment plan fields.');
    }
    private static function text($v,bool $empty=true): void
    {
        if(!is_string($v)||strlen($v)>120||(!$empty&&trim($v)==='')||preg_match('/[\x00-\x1f\x7f]/',$v))throw new InvalidArgumentException('Use a short deployment label without control characters.');
    }
    public static function validate(array $value,string $origin): array
    {
        self::fields($value,['authorities','peers','recoveryLocations']);
        foreach(['authorities'=>3,'peers'=>2,'recoveryLocations'=>2] as $key=>$count){
            if(!is_array($value[$key])||!array_is_list($value[$key])||count($value[$key])!==$count)throw new InvalidArgumentException('Plan three authority locations, two Symcon peers and two recovery locations.');
        }
        foreach(['authorities'=>'endpoint','peers'=>'origin'] as $list=>$address){
            $seen=[];
            foreach($value[$list] as &$item){
                if(!is_array($item))throw new InvalidArgumentException('Expected a deployment entry.');
                self::fields($item,['name',$address,'failureDomain']);self::text($item['name'],false);self::text($item['failureDomain']);
                if(!is_string($item[$address]))throw new InvalidArgumentException('Use an HTTPS origin or leave it unconfigured.');
                $item[$address]=SecretsFrontendConfiguration::origin($item[$address]);
                if($item[$address]!==''){
                    if(isset($seen[$item[$address]]))throw new InvalidArgumentException('Each authority/peer needs a distinct endpoint.');
                    $seen[$item[$address]]=true;
                }
                $item['name']=trim($item['name']);$item['failureDomain']=trim($item['failureDomain']);
            }
            unset($item);
        }
        // This code cannot nominate a different origin for the local installation.
        if($value['peers'][0]['origin']!==$origin)throw new InvalidArgumentException('The first peer must use this console-authorized HTTPS origin.');
        foreach($value['recoveryLocations'] as &$label){self::text($label);$label=trim($label);}unset($label);
        return $value;
    }
    public static function describe(array $plan,string $origin): array
    {
        $plan=self::validate($plan,$origin);$missing=[];
        foreach($plan['authorities'] as $i=>$a){if($a['endpoint']==='')$missing[]='Authority '.($i+1).': supply the gateway HTTPS address.';if($a['failureDomain']==='')$missing[]='Authority '.($i+1).': identify its independent power, storage and restore domain.';}
        foreach($plan['peers'] as $i=>$p){if($p['origin']==='')$missing[]='Symcon peer '.($i+1).': supply its administrator HTTPS address.';if($p['failureDomain']==='')$missing[]='Symcon peer '.($i+1).': identify its failure domain.';}
        $domains=array_map(static fn($x)=>strtolower($x['failureDomain']),$plan['authorities']);
        if(count(array_unique(array_filter($domains, static fn($x)=>$x!=='')))!==3)$missing[]='The three authority locations need distinct, independently verified failure domains.';
        $domains=array_map(static fn($x)=>strtolower($x['failureDomain']),$plan['peers']);
        if(count(array_unique(array_filter($domains, static fn($x)=>$x!=='')))!==2)$missing[]='The two Symcon peers must survive independently.';
        foreach($plan['recoveryLocations'] as $i=>$location)if($location==='')$missing[]='Recovery copy '.($i+1).': choose a separate protected offline location.';
        if($plan['recoveryLocations'][0]!==''&&strcasecmp($plan['recoveryLocations'][0],$plan['recoveryLocations'][1])===0)$missing[]='Choose two different recovery locations.';
        return ['schema'=>'SECF.DeploymentDraft.v1','status'=>'DRAFT_NOT_ADMITTED','deployment'=>$plan,
            'defaults'=>['voters'=>3,'quorum'=>2,'durableCopies'=>2,'coordinatorLeaseSeconds'=>30,'keepaliveSeconds'=>5,'connectTimeoutSeconds'=>3,'requestTimeoutSeconds'=>10,'physicalAdministratorKeys'=>2,'offlineRecoveryCopies'=>2],
            'missing'=>$missing,'verificationRequired'=>['Verify the independent failure domains. Labels alone do not establish independence.','Install the services and verify their TLS, receipt keys and native authority lineage.','Independently admit each host, boot and storage generation.','Verify peer and recovery envelopes on separate installations.','Enroll and test administrator keys, then complete full-system acceptance.'],
            'activationAllowed'=>false];
    }
}
