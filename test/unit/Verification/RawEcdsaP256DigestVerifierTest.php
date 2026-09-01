<?php

declare(strict_types=1);

namespace ThePhpFoundation\UnitTest\Attestation\Verification;

use OpenSSLAsymmetricKey;
use PHPUnit\Framework\TestCase;
use ThePhpFoundation\Attestation\Verification\RawEcdsaP256DigestVerifier;
use Webmozart\Assert\Assert;

use function hash;
use function openssl_pkey_get_details;
use function openssl_pkey_new;
use function openssl_sign;

use const OPENSSL_ALGO_SHA256;
use const OPENSSL_KEYTYPE_EC;

/** @covers \ThePhpFoundation\Attestation\Verification\RawEcdsaP256DigestVerifier */
final class RawEcdsaP256DigestVerifierTest extends TestCase
{
    /** @return array{0: OpenSSLAsymmetricKey, 1: non-empty-string, 2: non-empty-string} [private key, public key X, public key Y] */
    private static function newP256KeyPair(): array
    {
        $privateKey = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
        Assert::notFalse($privateKey);

        $details = openssl_pkey_get_details($privateKey);
        Assert::isArray($details);
        Assert::isArray($details['ec']);
        Assert::stringNotEmpty($details['ec']['x']);
        Assert::stringNotEmpty($details['ec']['y']);

        return [$privateKey, $details['ec']['x'], $details['ec']['y']];
    }

    public function testVerifiesAValidSignatureAgainstItsDigest(): void
    {
        [$privateKey, $qx, $qy] = self::newP256KeyPair();

        openssl_sign('signed content', $signature, $privateKey, OPENSSL_ALGO_SHA256);
        Assert::stringNotEmpty($signature);

        self::assertTrue(RawEcdsaP256DigestVerifier::verify(hash('sha256', 'signed content', true), $signature, $qx, $qy));
    }

    public function testRejectsASignatureAgainstADigestOfDifferentContent(): void
    {
        [$privateKey, $qx, $qy] = self::newP256KeyPair();

        openssl_sign('signed content', $signature, $privateKey, OPENSSL_ALGO_SHA256);
        Assert::stringNotEmpty($signature);

        self::assertFalse(RawEcdsaP256DigestVerifier::verify(hash('sha256', 'different content', true), $signature, $qx, $qy));
    }

    public function testRejectsAValidSignatureAgainstTheWrongPublicKey(): void
    {
        [$privateKey]          = self::newP256KeyPair();
        [, $wrongQx, $wrongQy] = self::newP256KeyPair();

        openssl_sign('signed content', $signature, $privateKey, OPENSSL_ALGO_SHA256);
        Assert::stringNotEmpty($signature);

        self::assertFalse(RawEcdsaP256DigestVerifier::verify(hash('sha256', 'signed content', true), $signature, $wrongQx, $wrongQy));
    }
}
