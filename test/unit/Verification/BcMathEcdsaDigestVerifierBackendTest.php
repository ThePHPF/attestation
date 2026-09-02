<?php

declare(strict_types=1);

namespace ThePhpFoundation\UnitTest\Attestation\Verification;

use OpenSSLAsymmetricKey;
use PHPUnit\Framework\TestCase;
use ThePhpFoundation\Attestation\Verification\BcMathEcdsaDigestVerifierBackend;
use ThePhpFoundation\Attestation\Verification\Der;
use Webmozart\Assert\Assert;

use function bin2hex;
use function extension_loaded;
use function hash;
use function ltrim;
use function openssl_pkey_get_details;
use function openssl_pkey_new;
use function openssl_sign;

use const OPENSSL_ALGO_SHA256;
use const OPENSSL_ALGO_SHA384;
use const OPENSSL_KEYTYPE_EC;

/** @covers \ThePhpFoundation\Attestation\Verification\BcMathEcdsaDigestVerifierBackend */
final class BcMathEcdsaDigestVerifierBackendTest extends TestCase
{
    private const CURVE_P256 = [
        'p' => 'FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF',
        'a' => 'FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC',
        'gx' => '6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296',
        'gy' => '4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5',
        'n' => 'FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551',
    ];

    private const CURVE_P384 = [
        'p' => 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF',
        'a' => 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFC',
        'gx' => 'AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7',
        'gy' => '3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F',
        'n' => 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973',
    ];

    protected function setUp(): void
    {
        if (extension_loaded('bcmath')) {
            return;
        }

        self::markTestSkipped('ext-bcmath is not loaded');
    }

    /** @return array{0: OpenSSLAsymmetricKey, 1: non-empty-string, 2: non-empty-string} [private key, public key X, public key Y] */
    private static function newKeyPair(string $curveName): array
    {
        $privateKey = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => $curveName]);
        Assert::notFalse($privateKey);

        $details = openssl_pkey_get_details($privateKey);
        Assert::isArray($details);
        Assert::isArray($details['ec']);
        Assert::stringNotEmpty($details['ec']['x']);
        Assert::stringNotEmpty($details['ec']['y']);

        return [$privateKey, $details['ec']['x'], $details['ec']['y']];
    }

    /** @return array{0: non-empty-string, 1: non-empty-string} [r as hex, s as hex] */
    private static function parseSignature(string $signatureDer): array
    {
        [, $sequenceContent]       = Der::readTlv($signatureDer, 0);
        [, $rValue, $offsetAfterR] = Der::readTlv($sequenceContent, 0);
        [, $sValue]                = Der::readTlv($sequenceContent, $offsetAfterR);

        $rHex = bin2hex(ltrim($rValue, "\x00"));
        $sHex = bin2hex(ltrim($sValue, "\x00"));
        Assert::stringNotEmpty($rHex);
        Assert::stringNotEmpty($sHex);

        return [$rHex, $sHex];
    }

    public function testVerifiesAValidP256SignatureAgainstItsDigest(): void
    {
        [$privateKey, $qx, $qy] = self::newKeyPair('prime256v1');

        openssl_sign('signed content', $signature, $privateKey, OPENSSL_ALGO_SHA256);
        Assert::stringNotEmpty($signature);
        [$rHex, $sHex] = self::parseSignature($signature);

        self::assertTrue((new BcMathEcdsaDigestVerifierBackend())->verify(self::CURVE_P256, hash('sha256', 'signed content', true), $rHex, $sHex, $qx, $qy));
    }

    public function testRejectsAP256SignatureAgainstADigestOfDifferentContent(): void
    {
        [$privateKey, $qx, $qy] = self::newKeyPair('prime256v1');

        openssl_sign('signed content', $signature, $privateKey, OPENSSL_ALGO_SHA256);
        Assert::stringNotEmpty($signature);
        [$rHex, $sHex] = self::parseSignature($signature);

        self::assertFalse((new BcMathEcdsaDigestVerifierBackend())->verify(self::CURVE_P256, hash('sha256', 'different content', true), $rHex, $sHex, $qx, $qy));
    }

    public function testRejectsAValidP256SignatureAgainstTheWrongPublicKey(): void
    {
        [$privateKey]          = self::newKeyPair('prime256v1');
        [, $wrongQx, $wrongQy] = self::newKeyPair('prime256v1');

        openssl_sign('signed content', $signature, $privateKey, OPENSSL_ALGO_SHA256);
        Assert::stringNotEmpty($signature);
        [$rHex, $sHex] = self::parseSignature($signature);

        self::assertFalse((new BcMathEcdsaDigestVerifierBackend())->verify(self::CURVE_P256, hash('sha256', 'signed content', true), $rHex, $sHex, $wrongQx, $wrongQy));
    }

    public function testVerifiesAValidP384SignatureAgainstItsDigest(): void
    {
        [$privateKey, $qx, $qy] = self::newKeyPair('secp384r1');

        openssl_sign('signed content', $signature, $privateKey, OPENSSL_ALGO_SHA384);
        Assert::stringNotEmpty($signature);
        [$rHex, $sHex] = self::parseSignature($signature);

        self::assertTrue((new BcMathEcdsaDigestVerifierBackend())->verify(self::CURVE_P384, hash('sha384', 'signed content', true), $rHex, $sHex, $qx, $qy));
    }

    public function testRejectsAP384SignatureAgainstADigestOfDifferentContent(): void
    {
        [$privateKey, $qx, $qy] = self::newKeyPair('secp384r1');

        openssl_sign('signed content', $signature, $privateKey, OPENSSL_ALGO_SHA384);
        Assert::stringNotEmpty($signature);
        [$rHex, $sHex] = self::parseSignature($signature);

        self::assertFalse((new BcMathEcdsaDigestVerifierBackend())->verify(self::CURVE_P384, hash('sha384', 'different content', true), $rHex, $sHex, $qx, $qy));
    }

    public function testRejectsAValidP384SignatureAgainstTheWrongPublicKey(): void
    {
        [$privateKey]          = self::newKeyPair('secp384r1');
        [, $wrongQx, $wrongQy] = self::newKeyPair('secp384r1');

        openssl_sign('signed content', $signature, $privateKey, OPENSSL_ALGO_SHA384);
        Assert::stringNotEmpty($signature);
        [$rHex, $sHex] = self::parseSignature($signature);

        self::assertFalse((new BcMathEcdsaDigestVerifierBackend())->verify(self::CURVE_P384, hash('sha384', 'signed content', true), $rHex, $sHex, $wrongQx, $wrongQy));
    }
}
