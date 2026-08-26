<?php

declare(strict_types=1);

namespace ThePhpFoundation\Attestation;

use function wordwrap;

/** @internal This is not a public API, so should not be depended upon unless you accept the risk of BC breaks */
final class PemPublicKey
{
    /** @var non-empty-string */
    private string $base64EncodedDerBytes;

    /** @param non-empty-string $base64EncodedDerBytes */
    private function __construct(string $base64EncodedDerBytes)
    {
        $this->base64EncodedDerBytes = $base64EncodedDerBytes;
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
}
