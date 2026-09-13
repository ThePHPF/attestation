<?php

declare(strict_types=1);

namespace ThePhpFoundation\Attestation;

use Webmozart\Assert\Assert;

use function base64_decode;
use function wordwrap;

/** @internal This is not a public API, so should not be depended upon unless you accept the risk of BC breaks */
final class PemPublicKey
{
    /** @param non-empty-string $base64EncodedDerBytes */
    private function __construct(private string $base64EncodedDerBytes)
    {
    }

    /** @param non-empty-string $base64EncodedDerBytes */
    public static function fromBase64EncodedDerBytes(string $base64EncodedDerBytes): self
    {
        return new self($base64EncodedDerBytes);
    }

    /**
     * OpenSSL will not take the base64-encoded DER on its own; it wants it wrapped in a PEM envelope.
     *
     * @return non-empty-string
     */
    public function decoratedPublicKey(): string
    {
        return "-----BEGIN PUBLIC KEY-----\n"
            . wordwrap($this->base64EncodedDerBytes, 64, "\n", true) . "\n"
            . "-----END PUBLIC KEY-----\n";
    }

    /** @return non-empty-string raw (non-base64, non-PEM) DER-encoded SubjectPublicKeyInfo bytes */
    public function derEncodedBytes(): string
    {
        $decoded = base64_decode($this->base64EncodedDerBytes);
        Assert::stringNotEmpty($decoded);

        return $decoded;
    }
}
