<?php

declare(strict_types=1);

namespace ThePhpFoundation\Attestation;

use Webmozart\Assert\Assert;

use function array_key_exists;

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

        Assert::keyExists($bundle, 'dsseEnvelope');
        Assert::isArray($bundle['dsseEnvelope']);

        return new self(
            self::certificateFromVerificationMaterial($bundle['verificationMaterial']),
            DsseEnvelope::fromBundleDsseEnvelope($bundle['dsseEnvelope']),
        );
    }

    /**
     * Grab the certificate from either `certificate.rawBytes` or from
     * `x509CertificateChain.certificates.0.rawBytes` depending on the bundle
     *
     * @param array<array-key, mixed> $verificationMaterial
     */
    private static function certificateFromVerificationMaterial(array $verificationMaterial): PemCertificate
    {
        if (array_key_exists('certificate', $verificationMaterial)) {
            Assert::isArray($verificationMaterial['certificate']);
            Assert::keyExists($verificationMaterial['certificate'], 'rawBytes');
            Assert::stringNotEmpty($verificationMaterial['certificate']['rawBytes']);

            return PemCertificate::fromBase64EncodedDerBytes($verificationMaterial['certificate']['rawBytes']);
        }

        Assert::keyExists($verificationMaterial, 'x509CertificateChain');
        Assert::isArray($verificationMaterial['x509CertificateChain']);
        Assert::keyExists($verificationMaterial['x509CertificateChain'], 'certificates');
        Assert::isNonEmptyList($verificationMaterial['x509CertificateChain']['certificates']);

        $leafCertificate = $verificationMaterial['x509CertificateChain']['certificates'][0];
        Assert::isArray($leafCertificate);
        Assert::keyExists($leafCertificate, 'rawBytes');
        Assert::stringNotEmpty($leafCertificate['rawBytes']);

        return PemCertificate::fromBase64EncodedDerBytes($leafCertificate['rawBytes']);
    }
}
