<?php
declare(strict_types=1);

/** Fair background work, with a shared best-effort deadline across route failover. */
final class SecretsBackendPeerWork
{
    public const BUDGET=45.0;
    public const SETUP_BUDGET=90.0;
    public const PHASES=['delivery','health','mesh','providers','setup'];
    public const SETUP_PHASES=['delivery','setup','health','setup','mesh','setup','providers'];
    private float $deadline;
    private int $attempts=0;
    private float $budget;
    private $clock;
    public function __construct(?callable $clock=null,?float $budget=null,float $maximum=self::BUDGET) { $this->clock=$clock??static fn():float=>microtime(true);$this->budget=min(min(self::SETUP_BUDGET,max(0.0,$maximum)),max(0.0,$budget??self::BUDGET));$this->deadline=($this->clock)()+$this->budget; }
    public static function phpBudget(int $limit,float $elapsed=0.0,float $maximum=self::BUDGET):float { return $limit>0?min($maximum,max(0.0,$limit-5.0-max(0.0,$elapsed))):$maximum; }
    public function budgetMilliseconds():int { return (int)round($this->budget*1000); }
    public function remaining():float { return max(0.0,$this->deadline-($this->clock)()); }
    public function attempt(string $endpoint,bool $setup=false):float {
        $left=$this->remaining();if($left<0.1)throw new SecretsBackendNativePeerDeliveryFailure('timeout');
        ++$this->attempts;return min($left,$setup?(SecretsBackendNativeLegacyHTTPS::timeout($endpoint)===25.0?60.0:45.0):SecretsBackendNativeLegacyHTTPS::timeout($endpoint));
    }
    public function providerAttempt():void { ++$this->attempts; }
    /** Idle phases are cheap; stop after one phase actually attempted network I/O. */
    public function run(int $start,array $phases,callable $next,bool $setup=false):array {
        $order=$setup?self::SETUP_PHASES:self::PHASES;
        $out=[];$start=max(0,$start)%count($order);
        for($offset=0;$offset<count($order)&&$this->remaining()>=4.6;$offset++){
            $index=($start+$offset)%count($order);$next(($index+1)%count($order));
            $out=array_merge($out,$phases[$order[$index]]());
            if($this->attempts>0)break;
        }return $out;
    }
    public static function limits(?int $workerBudgetMs=null):array { return ['primaryTimeoutMs'=>15000,'backupTimeoutMs'=>25000,'workerBudgetMs'=>$workerBudgetMs??(int)round(1000*self::phpBudget((int)ini_get('max_execution_time'))),'phpExecutionLimitSeconds'=>max(0,(int)ini_get('max_execution_time'))]; }
}
