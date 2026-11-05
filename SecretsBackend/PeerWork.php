<?php
declare(strict_types=1);

/** Fair background work, with a shared best-effort deadline across route failover. */
final class SecretsBackendPeerWork
{
    public const BUDGET=45.0;
    public const PHASES=['delivery','health','mesh','providers'];
    private float $deadline;
    private int $attempts=0;
    private float $budget;
    private $clock;
    public function __construct(?callable $clock=null,?float $budget=null) { $this->clock=$clock??static fn():float=>microtime(true);$this->budget=min(self::BUDGET,max(0.0,$budget??self::BUDGET));$this->deadline=($this->clock)()+$this->budget; }
    public static function phpBudget(int $limit,float $elapsed=0.0):float { return $limit>0?min(self::BUDGET,max(0.0,$limit-5.0-max(0.0,$elapsed))):self::BUDGET; }
    public function budgetMilliseconds():int { return (int)round($this->budget*1000); }
    public function remaining():float { return max(0.0,$this->deadline-($this->clock)()); }
    public function attempt(string $endpoint):float {
        $left=$this->remaining();if($left<0.1)throw new SecretsBackendNativePeerDeliveryFailure('timeout');
        ++$this->attempts;return min($left,SecretsBackendNativeLegacyHTTPS::timeout($endpoint));
    }
    public function providerAttempt():void { ++$this->attempts; }
    /** Idle phases are cheap; stop after one phase actually attempted network I/O. */
    public function run(int $start,array $phases,callable $next):array {
        $out=[];$start=max(0,$start)%count(self::PHASES);
        for($offset=0;$offset<count(self::PHASES)&&$this->remaining()>=4.6;$offset++){
            $index=($start+$offset)%count(self::PHASES);$next(($index+1)%count(self::PHASES));
            $out=array_merge($out,$phases[self::PHASES[$index]]());
            if($this->attempts>0)break;
        }return $out;
    }
    public static function limits(?int $workerBudgetMs=null):array { return ['primaryTimeoutMs'=>15000,'backupTimeoutMs'=>25000,'workerBudgetMs'=>$workerBudgetMs??(int)round(1000*self::phpBudget((int)ini_get('max_execution_time'))),'phpExecutionLimitSeconds'=>max(0,(int)ini_get('max_execution_time'))]; }
}
