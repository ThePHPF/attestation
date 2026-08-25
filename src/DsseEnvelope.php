<?php

declare(strict_types=1);

namespace ThePhpFoundation\Attestation;

use Webmozart\Assert\Assert;

use function base64_decode;
use function sprintf;
use function strlen;

/** @internal This is not a public API, so should not be depended upon unless you accept the risk of BC breaks */
final class DsseEnvelope implements SigstoreBundleContent
{
    /** @var non-empty-string */
    public string $payload;
    /** @var non-empty-string */
    public string $payloadType;
    /** @var non-empty-string */
    public string $signature;

    /**
     * @param non-empty-string $payload
     * @param non-empty-string $payloadType
     * @param non-empty-string $signature
     */
    private function __construct(string $payload, string $payloadType, string $signature)
    {
        $this->payload     = $payload;
        $this->payloadType = $payloadType;
        $this->signature   = $signature;
    }

    /** @param array<array-key, mixed> $dsseEnvelope */
    public static function fromBundleDsseEnvelope(array $dsseEnvelope): self
    {
        Assert::keyExists($dsseEnvelope, 'payload');
        Assert::stringNotEmpty($dsseEnvelope['payload']);
        Assert::keyExists($dsseEnvelope, 'payloadType');
        Assert::stringNotEmpty($dsseEnvelope['payloadType']);
        Assert::keyExists($dsseEnvelope, 'signatures');
        Assert::isNonEmptyList($dsseEnvelope['signatures']);
        Assert::count($dsseEnvelope['signatures'], 1);
        Assert::isArray($dsseEnvelope['signatures'][0]);
        Assert::keyExists($dsseEnvelope['signatures'][0], 'sig');
        Assert::stringNotEmpty($dsseEnvelope['signatures'][0]['sig']);

        $decodedPayload = base64_decode($dsseEnvelope['payload']);
        Assert::stringNotEmpty($decodedPayload);

        $decodedSignature = base64_decode($dsseEnvelope['signatures'][0]['sig']);
        Assert::stringNotEmpty($decodedSignature);

        return new self(
            $decodedPayload,
            $dsseEnvelope['payloadType'],
            $decodedSignature,
        );
    }

    /**
     * The Pre-Authentication Encoding is what the DSSE signature is actually calculated over.
     *
     * @link https://github.com/secure-systems-lab/dsse/blob/master/protocol.md#protocol
     *
     * @return non-empty-string
     */
    public function preAuthenticationEncoding(): string
    {
        return sprintf(
            'DSSEv1 %d %s %d %s',
            strlen($this->payloadType),
            $this->payloadType,
            strlen($this->payload),
            $this->payload,
        );
    }
}
