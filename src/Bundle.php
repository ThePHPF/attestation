<?php

declare(strict_types=1);

namespace ThePhpFoundation\Attestation;

use Webmozart\Assert\Assert;

use function array_key_exists;

/** @internal This is not a public API, so should not be depended upon unless you accept the risk of BC breaks */
final class Bundle
{
    public PemCertificate $certificate;
    public SigstoreBundleContent $content;

    private function __construct(PemCertificate $certificate, SigstoreBundleContent $content)
    {
        $this->certificate = $certificate;
        $this->content     = $content;
    }

    /** @param array<array-key, mixed> $bundle */
    public static function fromBundle(array $bundle): self
    {
        Assert::keyExists($bundle, 'verificationMaterial');
        Assert::isArray($bundle['verificationMaterial']);

        return new self(
            self::certificateFromVerificationMaterial($bundle['verificationMaterial']),
            self::contentFromBundle($bundle),
        );
    }

    /** @param array<array-key, mixed> $bundle */
    private static function contentFromBundle(array $bundle): SigstoreBundleContent
    {
        if (array_key_exists('dsseEnvelope', $bundle)) {
            Assert::isArray($bundle['dsseEnvelope']);

            return DsseEnvelope::fromBundleDsseEnvelope($bundle['dsseEnvelope']);
        }

        Assert::keyExists($bundle, 'messageSignature');
        Assert::isArray($bundle['messageSignature']);

        return MessageSignature::fromBundleMessageSignature($bundle['messageSignature']);
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
