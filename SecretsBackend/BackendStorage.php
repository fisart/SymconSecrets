<?php
declare(strict_types=1);

/** Storage contract for the separate administrator application. */
interface SecretsBackendStorage
{
    public function read(bool $fresh = true): array;
    public function change(array $expectedHead, string $operationId, string $requestDigest, callable $mutate, array $audit = []): array;
    public function authorize(string $kind, string $actionDigest, array $validated, callable $validate, array $audit = []): array;
    public function opaque(string $value): string;
    public function put(string $id, string $kind, array $body, int $expires, ?array $audit = null): void;
    public function get(string $id, string $kind, bool $consume = false): array;
    public function delete(string $id): void;
    public function replace(string $id, string $kind, array $body, int $expires): void;
    public function rate(string $key, int $limit): void;
    public function auditRejected(array $context = []): void;
}
