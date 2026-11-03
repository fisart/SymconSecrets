<?php
declare(strict_types=1);
require_once __DIR__.'/BackupOriginPolicy.php';

/** Cross-origin enrollment has no session authority until exact primary approval. */
trait SecretsBackendConnectEnrollment
{
    private function primaryOrigin(): string { return $this->settings['primaryOrigin']??$this->settings['origin']; }
    private function originGeneration(array $state): string { return $this->settings['origin']===$this->primaryOrigin()?'':($state['policy']['backupOrigin']['generation']??''); }
    private function checkRoute(array $state,string $action): void
    {
        if($this->settings['origin']===$this->primaryOrigin())return;
        $p=$state['policy']['backupOrigin']??null;
        $restricted=in_array($action,['status','connectOptions','connectSubmit','connectProof','connectStatus'],true);
        SecretsBackendBackupOriginPolicy::requireRoute($state,$this->settings['origin'],$p['generation']??'',$restricted?'register-options':'authenticate');
    }
    private function eligibleOrigin(array $state,array $credential,bool $allowUntested=false): bool
    {
        if($this->settings['origin']===$this->primaryOrigin())return ($credential['origin']??$this->primaryOrigin())===$this->primaryOrigin();
        try { SecretsBackendBackupOriginPolicy::requireCredential($state,$credential,$this->settings['origin'],$this->originGeneration($state),$allowUntested);return true; }catch(Throwable $e){return false;}
    }
    private function routeCredential(array $state,array $credential,bool $allowUntested=false): void { if(!$this->eligibleOrigin($state,$credential,$allowUntested))throw new RuntimeException('Credential belongs to another or revoked origin.'); }
    private function connectCandidate(string $id,array $state): array
    {
        if(!($this->store instanceof SecretsBackendNativeStore)||$this->settings['origin']!==$this->primaryOrigin())throw new RuntimeException('Review backup enrollment at the primary address.');
        $c=$this->store->get($id,'connect-candidate');
        SecretsBackendBackupOriginPolicy::requireRoute($state,$c['origin'],$c['generation'],'register-options');
        if(!SecretsBackendCodec::same($c['head'],$this->store->head())||$c['expires']<time()||$c['rights']!==SecretsBackendBackupOriginPolicy::rights($state['policy']['backupOrigin'])||$c['entry']['administrator']!==$state['identity']['ownerId'])throw new RuntimeException('Candidate policy or administrator changed. Start enrollment again.');
        return $c;
    }
    private function connectEnrollment(string $action,array $data,array $current): array
    {
        if(!($this->store instanceof SecretsBackendNativeStore)||$this->settings['origin']===$this->primaryOrigin())throw new RuntimeException('Open the approved Connect address to register its separate passkey.');
        $p=$current['state']['policy']['backupOrigin'];
        // Repeatable browser-key proof for read-only activation state. This
        // endpoint never grants a session or authorizes another operation.
        if($action==='connectStatus'){
            self::exact($data,['candidate','digest','signature']);$c=$this->store->get($data['candidate'],'connect-candidate');
            if($c['origin']!==$this->settings['origin']||$c['generation']!==$p['generation']||$c['expires']<time()||!isset($c['key'])||!hash_equals(SecretsBootstrapVerifier::digest($c),$data['digest']))throw new RuntimeException('Backup setup expired or changed. Repeat Step 3 from the primary window.');
            $bytes=implode("\n",['SECF.CONNECT.STATUS.1',$c['origin'],$c['generation'],$data['candidate'],$data['digest']])."\n";
            SecretsBootstrapVerifier::verifySignature($bytes,$data['signature'],$c['key']);
            $entry=$current['state']['identity']['credentials'][$c['entry']['id']]??null;
            if($p['status']==='active'){
                if(!is_array($entry)||!$this->eligibleOrigin($current['state'],$entry)||$entry['publicKey']!==$c['entry']['publicKey']||$entry['administrator']!==$c['entry']['administrator']||$entry['userHandle']!==$c['entry']['userHandle'])return ['state'=>'not-approved'];
                return ['state'=>'active'];
            }
            if(!SecretsBackendCodec::same($c['head'],$current['head']))throw new RuntimeException('Backup setup changed. Repeat Step 3 from the primary window.');
            return ['state'=>'waiting'];
        }
        if($p['status']!=='pending')throw new RuntimeException('No backup enrollment is pending.');
        $hardware=in_array(true,$current['state']['policy']['hardware'],true);
        if($action==='connectOptions'){
            self::exact($data,['key']);$key=SecretsBootstrapVerifier::publicKey($data['key']);
            $auth=$this->webauthn($hardware);$user=SecretsBackendCodec::b64(random_bytes(32));
            $args=$auth->getCreateArgs(SecretsBackendCodec::unb64($user),'Connect backup','Connect backup',90,'preferred',true,$hardware?true:null);
            if($hardware)$args->publicKey->attestation='direct';
            $id=SecretsBackendCodec::b64(random_bytes(32));
            $ctx=['challenge'=>SecretsBackendCodec::b64($auth->getChallenge()->getBinaryString()),'origin'=>$p['origin'],'owner'=>$current['state']['identity']['ownerId'],'userHandle'=>$user];
            $this->store->put($id,'connect-register',['context'=>$ctx,'key'=>$data['key'],'keyDigest'=>$key['digest'],'generation'=>$p['generation'],'head'=>$current['head'],'hardware'=>$hardware],time()+90);
            return ['prepare'=>$id,'options'=>$args->publicKey];
        }
        if($action==='connectSubmit'){
            self::exact($data,['prepare','credential','signature']);$r=$this->store->get($data['prepare'],'connect-register',true);
            if($r['generation']!==$p['generation']||!SecretsBackendCodec::same($r['head'],$current['head']))throw new RuntimeException('Backup enrollment changed.');
            $bytes=implode("\n",['SECF.CONNECT.REGISTER.1',$p['origin'],$p['generation'],$data['prepare'],$r['keyDigest'],SecretsBootstrapVerifier::digest($data['credential'])])."\n";
            SecretsBootstrapVerifier::verifySignature($bytes,$data['signature'],$r['key']);
            $entry=SecretsBootstrapVerifier::registration($data['credential'],$r['context']);$entry['label']='Connect backup';$entry['hardware']=$r['hardware'];$entry['trustVersion']=$this->settings['hardwareTrustVersion']??'none';
            if($entry['hardware']){if($entry['backupEligible'])throw new RuntimeException('Hardware credential cannot be backup eligible.');SecretsBackendHardwareTrust::verify(SecretsBackendCodec::unb64($data['credential']['response']['attestationObject']),$this->settings['hardwareRoots'],$this->settings['hardwareAAGUIDs'],hex2bin($entry['aaguid']));}
            if(isset($current['state']['identity']['credentials'][$entry['id']]))throw new RuntimeException('Credential already enrolled.');
            $auth=$this->webauthn();$args=$auth->getGetArgs([SecretsBackendCodec::unb64($entry['id'])],90,true,true,true,true,true,true);
            $id=SecretsBackendCodec::b64(random_bytes(32));
            $this->store->put($id,'connect-test',$r+['entry'=>$entry,'challenge'=>SecretsBackendCodec::b64($auth->getChallenge()->getBinaryString())],time()+90);
            return ['test'=>$id,'options'=>$args->publicKey,'generation'=>$p['generation']];
        }
        self::exact($data,['test','credential','signature']);$r=$this->store->get($data['test'],'connect-test',true);
        if($r['generation']!==$p['generation']||!SecretsBackendCodec::same($r['head'],$current['head']))throw new RuntimeException('Backup enrollment changed.');
        $bytes=implode("\n",['SECF.CONNECT.TEST.1',$p['origin'],$p['generation'],$data['test'],$r['keyDigest'],SecretsBootstrapVerifier::digest($data['credential'])])."\n";
        SecretsBootstrapVerifier::verifySignature($bytes,$data['signature'],$r['key']);
        $entry=$r['entry'];$entry['counter']=SecretsBootstrapVerifier::assertion($entry,$data['credential'],$r['challenge'],$p['origin']);$entry['tested']=true;$entry['origin']=$p['origin'];$entry['originGeneration']=$p['generation'];$entry['rights']=SecretsBackendBackupOriginPolicy::rights($p);
        $id=SecretsBackendCodec::b64(random_bytes(32));$candidate=['entry'=>$entry,'origin'=>$p['origin'],'generation'=>$p['generation'],'head'=>$current['head'],'keyDigest'=>$r['keyDigest'],'key'=>$r['key'],'rights'=>SecretsBackendBackupOriginPolicy::rights($p),'expires'=>time()+300];
        $this->store->put($id,'connect-candidate',$candidate,$candidate['expires']);
        return ['candidate'=>$id,'digest'=>SecretsBootstrapVerifier::digest($candidate),'fingerprint'=>hash('sha256',$entry['publicKey'])];
    }
}
