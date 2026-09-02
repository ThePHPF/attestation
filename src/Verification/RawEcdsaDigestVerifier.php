<?php

declare(strict_types=1);

namespace ThePhpFoundation\Attestation\Verification;

use Webmozart\Assert\Assert;

use function array_key_exists;
use function bin2hex;
use function extension_loaded;
use function ltrim;

/**
 * Verifies an ECDSA signature against an already-computed digest (rather than the signed message itself),
 * which ext-openssl has no way to do: openssl_verify() always hashes the message it's given internally.
 *
 * Prefers ext-gmp when available (consistently fast regardless of PHP version - unlike ext-bcmath, whose
 * performance varies a great deal by PHP version, see BcMathEcdsaDigestVerifierBackend), falling back to
 * ext-bcmath otherwise. Callers must check extension_loaded('gmp') || extension_loaded('bcmath') first.
 *
 * @internal This is not a public API, so should not be depended upon unless you accept the risk of BC breaks
 *
 * @link https://github.com/sigstore/sigstore-js/blob/main/packages/conformance/src/commands/verify-bundle.ts
 *       sigstore-js hits the exact same ext-openssl/Node crypto gap and works around it with the `elliptic`
 *       npm package; this does the equivalent raw point arithmetic using ext-gmp/ext-bcmath instead of a
 *       dependency.
 */
final class RawEcdsaDigestVerifier
{
    private const CURVES = [
        'prime256v1' => [
            'p' => 'FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF',
            'a' => 'FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC',
            'gx' => '6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296',
            'gy' => '4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5',
            'n' => 'FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551',
        ],
        'secp384r1' => [
            'p' => 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF',
            'a' => 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFC',
            'gx' => 'AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7',
            'gy' => '3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F',
            'n' => 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973',
        ],
    ];

    public static function isCurveSupported(string $curveName): bool
    {
        return array_key_exists($curveName, self::CURVES);
    }

    /**
     * @param non-empty-string $curveName    an OpenSSL EC curve name, e.g. 'prime256v1' or 'secp384r1'
     * @param non-empty-string $digest       raw digest bytes
     * @param non-empty-string $signatureDer ASN.1 DER SEQUENCE{INTEGER r, INTEGER s}
     * @param non-empty-string $qxBytes      public key X coordinate, raw bytes
     * @param non-empty-string $qyBytes      public key Y coordinate, raw bytes
     */
    public static function verify(string $curveName, string $digest, string $signatureDer, string $qxBytes, string $qyBytes): bool
    {
        Assert::keyExists(self::CURVES, $curveName);
        $curve = self::CURVES[$curveName];

        [$rHex, $sHex] = self::parseSignature($signatureDer);

        $backend = self::backend();

        return $backend->verify($curve, $digest, $rHex, $sHex, $qxBytes, $qyBytes);
    }

    private static function backend(): EcdsaDigestVerifierBackend
    {
        if (extension_loaded('gmp')) {
            return new GmpEcdsaDigestVerifierBackend();
        }

        return new BcMathEcdsaDigestVerifierBackend();
    }

    /** @return array{0: non-empty-string, 1: non-empty-string} [r as hex, s as hex] */
    private static function parseSignature(string $signatureDer): array
    {
        [$sequenceTag, $sequenceContent] = Der::readTlv($signatureDer, 0);
        Assert::same($sequenceTag, Der::TAG_SEQUENCE);

        [$rTag, $rValue, $offsetAfterR] = Der::readTlv($sequenceContent, 0);
        Assert::same($rTag, Der::TAG_INTEGER);

        [$sTag, $sValue] = Der::readTlv($sequenceContent, $offsetAfterR);
        Assert::same($sTag, Der::TAG_INTEGER);

        $rHex = bin2hex(ltrim($rValue, "\x00"));
        $sHex = bin2hex(ltrim($sValue, "\x00"));

        Assert::stringNotEmpty($rHex);
        Assert::stringNotEmpty($sHex);

        return [$rHex, $sHex];
    }
}
