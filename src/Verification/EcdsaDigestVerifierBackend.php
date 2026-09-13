<?php

declare(strict_types=1);

namespace ThePhpFoundation\Attestation\Verification;

/**
 * @internal This is not a public API, so should not be depended upon unless you accept the risk of BC breaks
 *
 * @phpstan-type EcdsaCurve array{p: non-empty-string, a: non-empty-string, gx: non-empty-string, gy: non-empty-string, n: non-empty-string}
 */
interface EcdsaDigestVerifierBackend
{
    /**
     * @param EcdsaCurve       $curve   hex-encoded curve parameters
     * @param non-empty-string $digest  raw digest bytes
     * @param non-empty-string $rHex    signature r, hex-encoded
     * @param non-empty-string $sHex    signature s, hex-encoded
     * @param non-empty-string $qxBytes public key X coordinate, raw bytes
     * @param non-empty-string $qyBytes public key Y coordinate, raw bytes
     */
    public function verify(array $curve, string $digest, string $rHex, string $sHex, string $qxBytes, string $qyBytes): bool;
}
