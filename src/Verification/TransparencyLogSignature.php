<?php

declare(strict_types=1);

namespace ThePhpFoundation\Attestation\Verification;

use ThePhpFoundation\Attestation\PemPublicKey;
use ThePhpFoundation\Attestation\Verification\Exception\NoSodium;
use Webmozart\Assert\Assert;

use function extension_loaded;
use function openssl_pkey_get_public;
use function openssl_verify;
use function sodium_crypto_sign_verify_detached;
use function strlen;
use function substr;

use const OPENSSL_ALGO_SHA256;

/**
 * @internal This is not a public API, so should not be depended upon unless you accept the risk of BC breaks
 *
 * @phpstan-import-type TransparencyLogKey from TrustedRoot
 */
final class TransparencyLogSignature
{
    private const ED25519_SPKI_DER_PREFIX_LENGTH = 12;
    private const ED25519_RAW_PUBLIC_KEY_LENGTH  = 32;

    /**
     * @param TransparencyLogKey $transparencyLogKey
     * @param non-empty-string   $signedContent
     * @param non-empty-string   $signature
     */
    public static function verify(array $transparencyLogKey, string $signedContent, string $signature): bool
    {
        if ($transparencyLogKey['keyDetails'] === TrustedRoot::KEY_DETAILS_ED25519) {
            if (! extension_loaded('sodium')) {
                throw NoSodium::new();
            }

            return sodium_crypto_sign_verify_detached(
                $signature,
                $signedContent,
                self::extractRawEd25519PublicKey($transparencyLogKey['publicKey']),
            );
        }

        $publicKey = openssl_pkey_get_public($transparencyLogKey['publicKey']->decoratedPublicKey());
        Assert::notFalse($publicKey);

        return openssl_verify($signedContent, $signature, $publicKey, OPENSSL_ALGO_SHA256) === 1;
    }

    /** @return non-empty-string */
    private static function extractRawEd25519PublicKey(PemPublicKey $publicKey): string
    {
        $derEncodedBytes = $publicKey->derEncodedBytes();
        Assert::same(strlen($derEncodedBytes), self::ED25519_SPKI_DER_PREFIX_LENGTH + self::ED25519_RAW_PUBLIC_KEY_LENGTH);

        return substr($derEncodedBytes, -self::ED25519_RAW_PUBLIC_KEY_LENGTH);
    }
}
