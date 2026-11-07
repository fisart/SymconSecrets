<?php
declare(strict_types=1);

/** Diagnostic age allowance only; never session, setup capability or read authority. */
final class SecretsBackendMonitoringFreshness
{
    public const MINIMUM=900;
    public const MAXIMUM=1800;
    private const SAMPLES=8;
    private static function gaps(array $cadence):array {
        return array_slice(array_values(array_filter($cadence['gaps']??[],static fn($v)=>is_int($v)&&$v>0&&$v<self::MAXIMUM)),-self::SAMPLES);
    }
    public static function seconds(array $cadence=[]):int {
        return min(self::MAXIMUM,max(self::MINIMUM,3*max([0,...self::gaps($cadence)])));
    }
    /** Learn only consecutive successful observations still within the prior allowance.
     * Failed checks, clock reversals and overdue/outage gaps cannot raise the limit.
     * The bounded recent window eventually forgets isolated slow cycles.
     */
    public static function observe(array $previous,int $now,bool $healthy):array {
        $gaps=self::gaps($previous);$last=$previous['lastAt']??null;
        if($healthy&&($previous['healthy']??false)&&is_int($last)&&$now>$last&&$now-$last<self::seconds($previous))$gaps[]=$now-$last;
        return ['gaps'=>array_slice($gaps,-self::SAMPLES),'lastAt'=>$now,'healthy'=>$healthy&&(!is_int($last)||$now>$last)];
    }
}
