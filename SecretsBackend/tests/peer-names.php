<?php
require_once __DIR__.'/../PeerName.php';
function nameCheck($actual,$expected){if($actual!==$expected)throw new RuntimeException('Unexpected peer display name.');}
$p=['name'=>'Peer 4444cabf','descriptor'=>['endpoint'=>'https://heartbeat.ap-fischer.de:46901/hook/secrets_peer_39686']];
nameCheck(SecretsBackendPeerName::display($p),'heartbeat.ap-fischer.de:46901');
$p['name']='Heartbeat';nameCheck(SecretsBackendPeerName::display($p),'Heartbeat');
$p['name']='Peer 4444cabf';$p['descriptor']['endpoint']='https://'.str_repeat('a',32).'.ipmagic.de/hook/secrets_peer_39686';$p['routes']['endpoints']=[$p['descriptor']['endpoint'],'https://heartbeat.ap-fischer.de:46901/hook/secrets_peer_39686'];nameCheck(SecretsBackendPeerName::display($p),'heartbeat.ap-fischer.de:46901');
$p['name']='';nameCheck(SecretsBackendPeerName::display($p),'heartbeat.ap-fischer.de:46901');
nameCheck(SecretsBackendPeerName::address('https://test.example:46910/hook/secrets_peer_11'),'test.example:46910');
echo "PASS peer names: old placeholders, preserved custom names, primary over Magic and distinct ports\n";
