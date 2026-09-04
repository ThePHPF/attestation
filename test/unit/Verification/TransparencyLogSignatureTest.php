<?php

declare(strict_types=1);

namespace ThePhpFoundation\UnitTest\Attestation\Verification;

use OpenSSLAsymmetricKey;
use PHPUnit\Framework\TestCase;
use ThePhpFoundation\Attestation\PemPublicKey;
use ThePhpFoundation\Attestation\Verification\TransparencyLogSignature;
use ThePhpFoundation\Attestation\Verification\TrustedRoot;
use Webmozart\Assert\Assert;

use function base64_encode;
use function openssl_pkey_get_details;
use function openssl_pkey_new;
use function openssl_sign;
use function sodium_crypto_sign_detached;
use function sodium_crypto_sign_keypair;
use function sodium_crypto_sign_publickey;
use function sodium_crypto_sign_secretkey;
use function str_replace;

use const OPENSSL_ALGO_SHA256;
use const OPENSSL_KEYTYPE_EC;

/** @covers \ThePhpFoundation\Attestation\Verification\TransparencyLogSignature */
final class TransparencyLogSignatureTest extends TestCase
{
    private const ED25519_SPKI_DER_PREFIX = "\x30\x2a\x30\x05\x06\x03\x2b\x65\x70\x03\x21\x00";

    /** @return array{0: OpenSSLAsymmetricKey, 1: PemPublicKey} */
    private static function newEcdsaKeyPair(): array
    {
        $privateKey = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
        Assert::notFalse($privateKey);

        $details = openssl_pkey_get_details($privateKey);
        Assert::isArray($details);
        Assert::stringNotEmpty($details['key']);

        $base64Der = str_replace(['-----BEGIN PUBLIC KEY-----', '-----END PUBLIC KEY-----', "\n"], '', $details['key']);
        Assert::stringNotEmpty($base64Der);

        return [$privateKey, PemPublicKey::fromBase64EncodedDerBytes($base64Der)];
    }

    /**
     * @param non-empty-string $keyDetails
     *
     * @return array{publicKey: PemPublicKey, keyId: non-empty-string, keyDetails: non-empty-string, validFor: array{start: int, end: int|null}}
     */
    private static function transparencyLogKey(PemPublicKey $publicKey, string $keyDetails): array
    {
        return [
            'publicKey' => $publicKey,
            'keyId' => 'irrelevant',
            'keyDetails' => $keyDetails,
            'validFor' => ['start' => 0, 'end' => null],
        ];
    }

    public function testVerifiesAValidEcdsaSignature(): void
    {
        [$privateKey, $publicKey] = self::newEcdsaKeyPair();

        openssl_sign('signed content', $signature, $privateKey, OPENSSL_ALGO_SHA256);
        Assert::stringNotEmpty($signature);

        self::assertTrue(TransparencyLogSignature::verify(
            self::transparencyLogKey($publicKey, TrustedRoot::KEY_DETAILS_ECDSA_P256_SHA_256),
            'signed content',
            $signature,
        ));
    }

    public function testRejectsAnEcdsaSignatureOverDifferentContent(): void
    {
        [$privateKey, $publicKey] = self::newEcdsaKeyPair();

        openssl_sign('signed content', $signature, $privateKey, OPENSSL_ALGO_SHA256);
        Assert::stringNotEmpty($signature);

        self::assertFalse(TransparencyLogSignature::verify(
            self::transparencyLogKey($publicKey, TrustedRoot::KEY_DETAILS_ECDSA_P256_SHA_256),
            'different content',
            $signature,
        ));
    }

    public function testVerifiesAValidEd25519Signature(): void
    {
        $keyPair   = sodium_crypto_sign_keypair();
        $secretKey = sodium_crypto_sign_secretkey($keyPair);
        $publicKey = PemPublicKey::fromBase64EncodedDerBytes(
            base64_encode(self::ED25519_SPKI_DER_PREFIX . sodium_crypto_sign_publickey($keyPair)),
        );

        $signature = sodium_crypto_sign_detached('signed content', $secretKey);

        self::assertTrue(TransparencyLogSignature::verify(
            self::transparencyLogKey($publicKey, TrustedRoot::KEY_DETAILS_ED25519),
            'signed content',
            $signature,
        ));
    }

    public function testRejectsAnEd25519SignatureOverDifferentContent(): void
    {
        $keyPair   = sodium_crypto_sign_keypair();
        $secretKey = sodium_crypto_sign_secretkey($keyPair);
        $publicKey = PemPublicKey::fromBase64EncodedDerBytes(
            base64_encode(self::ED25519_SPKI_DER_PREFIX . sodium_crypto_sign_publickey($keyPair)),
        );

        $signature = sodium_crypto_sign_detached('signed content', $secretKey);

        self::assertFalse(TransparencyLogSignature::verify(
            self::transparencyLogKey($publicKey, TrustedRoot::KEY_DETAILS_ED25519),
            'different content',
            $signature,
        ));
    }
}
