<?php
declare(strict_types=1);
require_once __DIR__ . '/../ConnectDiscovery.php';

function discoverExpect(bool $value, string $message): void { if (!$value) throw new RuntimeException($message); }
$instances=static fn($module)=>$module===SecretsFrontendConnectDiscovery::MODULE?[123]:[];
$active=static fn($id)=>102;
$check=static fn($value)=>SecretsFrontendConnectDiscovery::discover($instances,$active,static fn($id)=>$value);
$good=$check('https://example.ipmagic.de/');
discoverExpect($good===['available'=>true,'origin'=>'https://example.ipmagic.de'],'Valid Connect origin not suggested.');
foreach (['','http://example.ipmagic.de','https://example.ipmagic.de/path','https://user@example.ipmagic.de','https://192.0.2.1',null] as $bad) discoverExpect($check($bad)['available']===false,'Invalid discovery suggested.');
discoverExpect(!SecretsFrontendConnectDiscovery::discover(static fn($m)=>[],$active,static fn($id)=>'https://example.ipmagic.de')['available'],'Missing instance accepted.');
discoverExpect(!SecretsFrontendConnectDiscovery::discover(static fn($m)=>[1,2],$active,static fn($id)=>'https://example.ipmagic.de')['available'],'Ambiguous instance accepted.');
discoverExpect(!SecretsFrontendConnectDiscovery::discover($instances,static fn($id)=>104,static fn($id)=>'https://example.ipmagic.de')['available'],'Inactive instance accepted.');
discoverExpect(!SecretsFrontendConnectDiscovery::discover($instances,$active,static function($id){throw new RuntimeException('not available');})['available'],'Unavailable function accepted.');
echo "Connect discovery checks passed.\n";
