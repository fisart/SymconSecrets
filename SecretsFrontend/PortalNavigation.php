<?php
declare(strict_types=1);

/** Frontend-owned lookup: original library helpers remain untouched for legacy installations. */
    final class SecretsFrontendPortalNavigation
    {
        private const PORTAL = '{922E5A10-A048-463D-A973-97B4BBD9096B}';
        private const VAULT = '{7C5A3841-3F7B-4D2A-9E1C-5B6D8F9A0E12}';
        private const BACKEND = '{52165EDD-B2C0-40EC-8A59-42A97319B6E2}';
        private const WEBHOOKS = '{015A6EB8-D6E5-4B93-B496-0D3F77AE9FE1}';

        private static function nativeBackend(int $id): int
        {
            if ($id<=0||!IPS_InstanceExists($id)||(function_exists('IPS_HasChanges')&&IPS_HasChanges($id))) return 0;
            $module=strtoupper((string)(IPS_GetInstance($id)['ModuleInfo']['ModuleID']??''));
            if ($module===self::BACKEND) return IPS_GetProperty($id,'Enabled')===true?$id:0;
            if ($module!==self::VAULT||!function_exists('SEC_GetReplacementInfo')) return 0;
            $info=json_decode(SEC_GetReplacementInfo($id),true,32,JSON_THROW_ON_ERROR);$backend=$info['backend']??0;
            if (($info['engine']??'')!=='native-only'||($info['ready']??false)!==true||!is_int($backend)||$backend<=0||!IPS_InstanceExists($backend)||strtoupper((string)(IPS_GetInstance($backend)['ModuleInfo']['ModuleID']??''))!==self::BACKEND) return 0;
            return self::nativeBackend($backend);
        }
        private static function identity(int $id): string
        {
            $backend=self::nativeBackend($id);return $backend?'native:'.$backend:'old:'.$id;
        }
        private static function validVault(int $id): bool
        {
            try {
                if ($id<=0||!IPS_InstanceExists($id)||(function_exists('IPS_HasChanges')&&IPS_HasChanges($id))) return false;
                $backend=self::nativeBackend($id);
                if ($backend) $value=IPS_GetProperty($backend,'AdminOrigin');
                else {
                    if (function_exists('SEC_GetReplacementInfo')||strtoupper((string)(IPS_GetInstance($id)['ModuleInfo']['ModuleID']??''))!==self::VAULT||IPS_GetProperty($id,'PortalEnabled')!==true) return false;
                    $value=IPS_GetProperty($id,'PortalOrigin');
                }
                $origin=parse_url((string)$value);
                return is_array($origin)&&($origin['scheme']??'')==='https'&&!empty($origin['host'])&&!isset($origin['user'])&&!isset($origin['pass'])&&!isset($origin['query'])&&!isset($origin['fragment'])&&in_array($origin['path']??'',['','/'],true);
            } catch (Throwable $e) { return false; }
        }
        private static function vaultForPortal(int $selection): int
        {
            if ($selection>0) return self::validVault($selection)?$selection:0;
            $eligible=[];
            foreach (array_merge(IPS_GetInstanceListByModuleID(self::BACKEND),IPS_GetInstanceListByModuleID(self::VAULT)) as $id) {
                $id=(int)$id;
                if (self::validVault($id)) $eligible[self::identity($id)]=$id;
            }
            return count($eligible)===1?array_values($eligible)[0]:0;
        }

        /** Read native metadata only. Never invoke a destination or change an instance. */
        public static function path(int $vault = 0, int $preferred = 0): string
        {
            try {
                $controls = IPS_GetInstanceListByModuleID(self::WEBHOOKS);
                if (count($controls) !== 1) return '';
                $hooks = json_decode((string)IPS_GetProperty((int)$controls[0], 'Hooks'), true, 64, JSON_THROW_ON_ERROR);
                if (!is_array($hooks) || array_values($hooks) !== $hooks) return '';
                $ids = $preferred > 0 ? [$preferred] : IPS_GetInstanceListByModuleID(self::PORTAL);
                $eligible = [];
                foreach ($ids as $id) {
                    $id = (int)$id;
                    try {
                        if ($id <= 0 || !IPS_InstanceExists($id)
                            || strtoupper((string)(IPS_GetInstance($id)['ModuleInfo']['ModuleID'] ?? '')) !== self::PORTAL
                            || IPS_GetProperty($id, 'Enabled') !== true) continue;
                        $portalVault = self::vaultForPortal((int)IPS_GetProperty($id, 'VaultInstanceID'));
                        if ($portalVault === 0 || ($vault > 0 && (!self::validVault($vault)||self::identity($portalVault)!==self::identity($vault)))) continue;
                        $path = '/hook/alarm_portal_' . $id;
                        $matches = array_values(array_filter($hooks, static fn($hook) => is_array($hook) && ($hook['Hook'] ?? '') === $path));
                        if (count($matches) === 1 && (int)($matches[0]['TargetID'] ?? 0) === $id) $eligible[$id] = $path;
                    } catch (Throwable $e) { continue; }
                }
                return count($eligible) === 1 ? array_values($eligible)[0] : '';
            } catch (Throwable $e) { return ''; }
        }

    }
