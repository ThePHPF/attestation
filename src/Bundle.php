<?php

declare(strict_types=1);

namespace ThePhpFoundation\Attestation;

use Webmozart\Assert\Assert;

/** @internal This is not a public API, so should not be depended upon unless you accept the risk of BC breaks */
final class Bundle
{
    public PemCertificate $certificate;
    public DsseEnvelope $dsseEnvelope;

    private function __construct(PemCertificate $certificate, DsseEnvelope $dsseEnvelope)
    {
        $this->certificate  = $certificate;
        $this->dsseEnvelope = $dsseEnvelope;
    }

    /** @param array<array-key, mixed> $bundle */
    public static function fromBundleWithDsseEnvelope(array $bundle): self
    {
        Assert::keyExists($bundle, 'verificationMaterial');
        Assert::isArray($bundle['verificationMaterial']);
        Assert::keyExists($bundle['verificationMaterial'], 'certificate');
        Assert::isArray($bundle['verificationMaterial']['certificate']);
        Assert::keyExists($bundle['verificationMaterial']['certificate'], 'rawBytes');
        Assert::stringNotEmpty($bundle['verificationMaterial']['certificate']['rawBytes']);

        Assert::keyExists($bundle, 'dsseEnvelope');
        Assert::isArray($bundle['dsseEnvelope']);

        return new self(
            PemCertificate::fromBase64EncodedDerBytes($bundle['verificationMaterial']['certificate']['rawBytes']),
            DsseEnvelope::fromBundleDsseEnvelope($bundle['dsseEnvelope']),
        );
    }
}
