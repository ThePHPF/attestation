<?php

declare(strict_types=1);

namespace ThePhpFoundation\Attestation;

use Webmozart\Assert\Assert;

use function base64_decode;
use function wordwrap;

/** @internal This is not a public API, so should not be depended upon unless you accept the risk of BC breaks */
final class Attestation
{
    /** @var non-empty-string */
    public string $certificate;
    /** @var non-empty-string */
    public string $dsseEnvelopePayload;
    /** @var non-empty-string */
    public string $dsseEnvelopePayloadType;
    /** @var non-empty-string */
    public string $dsseEnvelopeSignature;

    /**
     * @param non-empty-string $certificate
     * @param non-empty-string $dsseEnvelopePayload
     * @param non-empty-string $dsseEnvelopePayloadType
     * @param non-empty-string $dsseEnvelopeSignature
     */
    private function __construct(
        string $certificate,
        string $dsseEnvelopePayload,
        string $dsseEnvelopePayloadType,
        string $dsseEnvelopeSignature
    ) {
        $this->dsseEnvelopeSignature   = $dsseEnvelopeSignature;
        $this->dsseEnvelopePayloadType = $dsseEnvelopePayloadType;
        $this->dsseEnvelopePayload     = $dsseEnvelopePayload;
        $this->certificate             = $certificate;
    }

    /** @param array<array-key, mixed> $bundle */
    public static function fromAttestationBundleWithDsseEnvelope(array $bundle): self
    {
        Assert::keyExists($bundle, 'verificationMaterial');
        Assert::isArray($bundle['verificationMaterial']);
        Assert::keyExists($bundle['verificationMaterial'], 'certificate');
        Assert::isArray($bundle['verificationMaterial']['certificate']);
        Assert::keyExists($bundle['verificationMaterial']['certificate'], 'rawBytes');
        Assert::stringNotEmpty($bundle['verificationMaterial']['certificate']['rawBytes']);

        Assert::keyExists($bundle, 'dsseEnvelope');
        Assert::isArray($bundle['dsseEnvelope']);
        Assert::keyExists($bundle['dsseEnvelope'], 'payload');
        Assert::stringNotEmpty($bundle['dsseEnvelope']['payload']);
        Assert::keyExists($bundle['dsseEnvelope'], 'payloadType');
        Assert::stringNotEmpty($bundle['dsseEnvelope']['payloadType']);
        Assert::keyExists($bundle['dsseEnvelope'], 'signatures');
        Assert::isNonEmptyList($bundle['dsseEnvelope']['signatures']);
        Assert::count($bundle['dsseEnvelope']['signatures'], 1);
        Assert::keyExists($bundle['dsseEnvelope']['signatures'], 0);
        Assert::isArray($bundle['dsseEnvelope']['signatures'][0]);
        Assert::keyExists($bundle['dsseEnvelope']['signatures'][0], 'sig');
        Assert::stringNotEmpty($bundle['dsseEnvelope']['signatures'][0]['sig']);

        $decoratedCertificate = "-----BEGIN CERTIFICATE-----\n"
            . wordwrap($bundle['verificationMaterial']['certificate']['rawBytes'], 67, "\n", true) . "\n"
            . "-----END CERTIFICATE-----\n";

        $decodedPayload = base64_decode($bundle['dsseEnvelope']['payload']);
        Assert::stringNotEmpty($decodedPayload);

        $decodedSignature = base64_decode($bundle['dsseEnvelope']['signatures'][0]['sig']);
        Assert::stringNotEmpty($decodedSignature);

        return new self(
            $decoratedCertificate,
            $decodedPayload,
            $bundle['dsseEnvelope']['payloadType'],
            $decodedSignature,
        );
    }
}
