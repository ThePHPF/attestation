<?php

declare(strict_types=1);

namespace ThePhpFoundation\UnitTest\Attestation;

use PHPUnit\Framework\TestCase;
use ThePhpFoundation\Attestation\PemPublicKey;

use function base64_decode;
use function openssl_pkey_get_public;

/** @covers \ThePhpFoundation\Attestation\PemPublicKey */
final class PemPublicKeyTest extends TestCase
{
    private const REAL_ECDSA_PUBLIC_KEY_DER = 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2G2Y+2tabdTV5BcGiBIx0a9fAFwrkBbmLSGtks4L3qX6yYY0zufBnhC8Ur/iy55GhWP/9A/bY2LhC30M9+RYtw==';

    public function testDecoratedPublicKeyIsWrappedInPemArmour(): void
    {
        $decoratedPublicKey = PemPublicKey::fromBase64EncodedDerBytes(self::REAL_ECDSA_PUBLIC_KEY_DER)
            ->decoratedPublicKey();

        self::assertStringStartsWith("-----BEGIN PUBLIC KEY-----\n", $decoratedPublicKey);
        self::assertStringEndsWith("-----END PUBLIC KEY-----\n", $decoratedPublicKey);
    }

    public function testDecoratedPublicKeyIsUsableByOpenSsl(): void
    {
        $decoratedPublicKey = PemPublicKey::fromBase64EncodedDerBytes(self::REAL_ECDSA_PUBLIC_KEY_DER)
            ->decoratedPublicKey();

        self::assertNotFalse(openssl_pkey_get_public($decoratedPublicKey));
    }

    public function testDerEncodedBytesReturnsRawDecodedBytes(): void
    {
        $derEncodedBytes = PemPublicKey::fromBase64EncodedDerBytes(self::REAL_ECDSA_PUBLIC_KEY_DER)
            ->derEncodedBytes();

        self::assertSame(base64_decode(self::REAL_ECDSA_PUBLIC_KEY_DER), $derEncodedBytes);
    }
}
