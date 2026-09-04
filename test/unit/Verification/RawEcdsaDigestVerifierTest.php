<?php

declare(strict_types=1);

namespace ThePhpFoundation\UnitTest\Attestation\Verification;

use OpenSSLAsymmetricKey;
use PHPUnit\Framework\TestCase;
use ThePhpFoundation\Attestation\Verification\RawEcdsaDigestVerifier;
use Webmozart\Assert\Assert;

use function hash;
use function openssl_pkey_get_details;
use function openssl_pkey_new;
use function openssl_sign;

use const OPENSSL_ALGO_SHA256;
use const OPENSSL_ALGO_SHA384;
use const OPENSSL_KEYTYPE_EC;

/** @covers \ThePhpFoundation\Attestation\Verification\RawEcdsaDigestVerifier */
final class RawEcdsaDigestVerifierTest extends TestCase
{
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

    public function testIsCurveSupportedRecognisesP256AndP384(): void
    {
        self::assertTrue(RawEcdsaDigestVerifier::isCurveSupported('prime256v1'));
        self::assertTrue(RawEcdsaDigestVerifier::isCurveSupported('secp384r1'));
        self::assertFalse(RawEcdsaDigestVerifier::isCurveSupported('secp256k1'));
    }

    public function testVerifiesAValidP256SignatureAgainstItsDigest(): void
    {
        [$privateKey, $qx, $qy] = self::newKeyPair('prime256v1');

        openssl_sign('signed content', $signature, $privateKey, OPENSSL_ALGO_SHA256);
        Assert::stringNotEmpty($signature);

        self::assertTrue(RawEcdsaDigestVerifier::verify('prime256v1', hash('sha256', 'signed content', true), $signature, $qx, $qy));
    }

    public function testRejectsAP256SignatureAgainstADigestOfDifferentContent(): void
    {
        [$privateKey, $qx, $qy] = self::newKeyPair('prime256v1');

        openssl_sign('signed content', $signature, $privateKey, OPENSSL_ALGO_SHA256);
        Assert::stringNotEmpty($signature);

        self::assertFalse(RawEcdsaDigestVerifier::verify('prime256v1', hash('sha256', 'different content', true), $signature, $qx, $qy));
    }

    public function testRejectsAValidP256SignatureAgainstTheWrongPublicKey(): void
    {
        [$privateKey]          = self::newKeyPair('prime256v1');
        [, $wrongQx, $wrongQy] = self::newKeyPair('prime256v1');

        openssl_sign('signed content', $signature, $privateKey, OPENSSL_ALGO_SHA256);
        Assert::stringNotEmpty($signature);

        self::assertFalse(RawEcdsaDigestVerifier::verify('prime256v1', hash('sha256', 'signed content', true), $signature, $wrongQx, $wrongQy));
    }

    public function testVerifiesAValidP384SignatureAgainstItsDigest(): void
    {
        [$privateKey, $qx, $qy] = self::newKeyPair('secp384r1');

        openssl_sign('signed content', $signature, $privateKey, OPENSSL_ALGO_SHA384);
        Assert::stringNotEmpty($signature);

        self::assertTrue(RawEcdsaDigestVerifier::verify('secp384r1', hash('sha384', 'signed content', true), $signature, $qx, $qy));
    }

    public function testRejectsAP384SignatureAgainstADigestOfDifferentContent(): void
    {
        [$privateKey, $qx, $qy] = self::newKeyPair('secp384r1');

        openssl_sign('signed content', $signature, $privateKey, OPENSSL_ALGO_SHA384);
        Assert::stringNotEmpty($signature);

        self::assertFalse(RawEcdsaDigestVerifier::verify('secp384r1', hash('sha384', 'different content', true), $signature, $qx, $qy));
    }

    public function testRejectsAValidP384SignatureAgainstTheWrongPublicKey(): void
    {
        [$privateKey]          = self::newKeyPair('secp384r1');
        [, $wrongQx, $wrongQy] = self::newKeyPair('secp384r1');

        openssl_sign('signed content', $signature, $privateKey, OPENSSL_ALGO_SHA384);
        Assert::stringNotEmpty($signature);

        self::assertFalse(RawEcdsaDigestVerifier::verify('secp384r1', hash('sha384', 'signed content', true), $signature, $wrongQx, $wrongQy));
    }
}
