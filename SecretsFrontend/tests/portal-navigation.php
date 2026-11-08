<?php
declare(strict_types=1);
// Reuse unchanged original metadata fixtures, then exercise the frontend-owned lookup.
require __DIR__.'/../../tests/system_portal_navigation.php';
require __DIR__.'/../PortalNavigation.php';
require __DIR__.'/../Http.php';
baseline();$GLOBALS['native'][5]['props']['Hooks']=json_encode([['Hook'=>'/hook/alarm_portal_43','TargetID'=>43],['Hook'=>'/hook/portal','TargetID'=>43]]);
expect(SecretsFrontendPortalNavigation::path(0,43)==='/hook/portal','Frontend keeps old manager Portal discovery');
$GLOBALS['native'][18]=['guid'=>'{52165EDD-B2C0-40EC-8A59-42A97319B6E2}','props'=>['Enabled'=>true,'AdminOrigin'=>'https://system.example']];$GLOBALS['native'][43]['props']['VaultInstanceID']=18;
expect(AFSystemPortalNavigationV1::path(0,43)==='','Fixture must reproduce old helper hiding a native Portal');
$portal=SecretsFrontendPortalNavigation::path(0,43);
expect($portal==='/hook/portal','Frontend discovers Portal configured with native backend');
$settings=array_replace(SecretsFrontendConfiguration::DEFAULTS,['Enabled'=>true,'AdminOrigin'=>'https://secrets.example.test','BackendInstanceID'=>18]);
$server=['REQUEST_METHOD'=>'GET','REQUEST_URI'=>'/hook/secrets_frontend_5200','HTTP_HOST'=>'secrets.example.test','REMOTE_ADDR'=>'127.0.0.1'];
$response=SecretsFrontendHttp::response($settings,5200,$server,'/hook/secrets_frontend_5200',$portal,'/hook/alarm_documentation_12');
expect($response['status']===200,'Frontend HTTP markup was not assembled');
expect(str_contains($response['body'],'id="portalLink" href="/hook/portal">Portal</a>'),'Header did not render the native Portal destination');
expect(strpos($response['body'],'id="portalLink"')<strpos($response['body'],'</header>'),'Portal link was not in the header');
$response=SecretsFrontendHttp::response($settings,5200,$server,'/hook/secrets_frontend_5200','','');
expect(str_contains($response['body'],'id="portalLinkUnavailable"'),'Unavailable Portal silently vanished');
$invalid=SecretsFrontendHttp::response($settings,5200,$server,'/hook/secrets_frontend_5200','https://evil.example','');
expect(!str_contains($invalid['body'],'href="https://evil.example"'),'Unsafe Portal target was rendered');
$GLOBALS['native'][18]['props']['Enabled']=false;expect(SecretsFrontendPortalNavigation::path(0,43)==='','Disabled native backend accepted');$GLOBALS['native'][18]['props']['Enabled']=true;
$GLOBALS['native'][5]['props']['Hooks']='[]';expect(SecretsFrontendPortalNavigation::path(0,43)==='','Unregistered Portal hook accepted');baseline();$GLOBALS['native'][5]['props']['Hooks']=json_encode([['Hook'=>'/hook/alarm_portal_43','TargetID'=>43],['Hook'=>'/hook/portal','TargetID'=>43]]);
if (!function_exists('SEC_GetReplacementInfo')) {
 function SEC_GetReplacementInfo(int $id):string {return json_encode(['engine'=>'native-only','ready'=>!($GLOBALS['bindingFailed']??false),'backend'=>18],JSON_THROW_ON_ERROR);}
}
$GLOBALS['native'][7]['props']['PortalEnabled']=false;$GLOBALS['native'][18]=['guid'=>'{52165EDD-B2C0-40EC-8A59-42A97319B6E2}','props'=>['Enabled'=>true,'AdminOrigin'=>'https://system.example']];
expect(SecretsFrontendPortalNavigation::path(18,43)==='/hook/portal','Adapter/backend identity did not match');
$GLOBALS['native'][43]['props']['VaultInstanceID']=0;expect(SecretsFrontendPortalNavigation::path(18,43)==='/hook/portal','Automatic native discovery counted adapter twice');
$GLOBALS['bindingFailed']=true;expect(SecretsFrontendPortalNavigation::path(7,43)==='','Failed native adapter fell back to inactive old settings');
echo "PASS frontend Portal header discovery for legacy/native/adapter, unavailable state and safe destinations.\n";
