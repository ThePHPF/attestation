<?php

declare(strict_types=1);

namespace ThePhpFoundation\Attestation;

use Webmozart\Assert\Assert;

use function wordwrap;

/** @internal This is not a public API, so should not be depended upon unless you accept the risk of BC breaks */
final class Attestation
{
    /** @var non-empty-string */
    public string $certificate;
    public DsseEnvelope $dsseEnvelope;

    /** @param non-empty-string $certificate */
    private function __construct(string $certificate, DsseEnvelope $dsseEnvelope)
    {
        $this->certificate  = $certificate;
        $this->dsseEnvelope = $dsseEnvelope;
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

        $decoratedCertificate = "-----BEGIN CERTIFICATE-----\n"
            . wordwrap($bundle['verificationMaterial']['certificate']['rawBytes'], 67, "\n", true) . "\n"
            . "-----END CERTIFICATE-----\n";

        return new self(
            $decoratedCertificate,
            DsseEnvelope::fromBundleDsseEnvelope($bundle['dsseEnvelope']),
        );
    }
}
