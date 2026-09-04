<?php

declare(strict_types=1);

namespace ThePhpFoundation\Attestation;

use Webmozart\Assert\Assert;

use function array_key_exists;
use function base64_decode;
use function is_array;

/** @internal This is not a public API, so should not be depended upon unless you accept the risk of BC breaks */
final class Bundle
{
    /**
     * @param non-empty-string           $mediaType
     * @param list<TransparencyLogEntry> $transparencyLogEntries
     * @param list<non-empty-string>     $rfc3161Timestamps
     */
    private function __construct(private string $mediaType, private PemCertificate $certificate, private SigstoreBundleContent $content, private array $transparencyLogEntries, private array $rfc3161Timestamps)
    {
    }

    /** @param array<array-key, mixed> $bundle */
    public static function fromBundle(array $bundle): self
    {
        Assert::keyExists($bundle, 'mediaType');
        Assert::stringNotEmpty($bundle['mediaType']);
        Assert::keyExists($bundle, 'verificationMaterial');
        Assert::isArray($bundle['verificationMaterial']);

        return new self(
            $bundle['mediaType'],
            self::certificateFromVerificationMaterial($bundle['verificationMaterial']),
            self::contentFromBundle($bundle),
            self::transparencyLogEntriesFromVerificationMaterial($bundle['verificationMaterial']),
            self::rfc3161TimestampsFromVerificationMaterial($bundle['verificationMaterial']),
        );
    }

    /** @return non-empty-string */
    public function mediaType(): string
    {
        return $this->mediaType;
    }

    public function certificate(): PemCertificate
    {
        return $this->certificate;
    }

    public function content(): SigstoreBundleContent
    {
        return $this->content;
    }

    /** @return list<TransparencyLogEntry> */
    public function transparencyLogEntries(): array
    {
        return $this->transparencyLogEntries;
    }

    /** @return list<non-empty-string> */
    public function rfc3161Timestamps(): array
    {
        return $this->rfc3161Timestamps;
    }

    /**
     * @param array<array-key, mixed> $verificationMaterial
     *
     * @return list<TransparencyLogEntry>
     */
    private static function transparencyLogEntriesFromVerificationMaterial(array $verificationMaterial): array
    {
        if (! array_key_exists('tlogEntries', $verificationMaterial)) {
            return [];
        }

        Assert::isArray($verificationMaterial['tlogEntries']);

        $transparencyLogEntries = [];
        foreach ($verificationMaterial['tlogEntries'] as $transparencyLogEntry) {
            Assert::isArray($transparencyLogEntry);
            $transparencyLogEntries[] = TransparencyLogEntry::fromBundleTransparencyLogEntry($transparencyLogEntry);
        }

        return $transparencyLogEntries;
    }

    /**
     * @param array<array-key, mixed> $verificationMaterial
     *
     * @return list<non-empty-string>
     */
    private static function rfc3161TimestampsFromVerificationMaterial(array $verificationMaterial): array
    {
        if (
            ! array_key_exists('timestampVerificationData', $verificationMaterial)
            || ! is_array($verificationMaterial['timestampVerificationData'])
            || ! array_key_exists('rfc3161Timestamps', $verificationMaterial['timestampVerificationData'])
        ) {
            return [];
        }

        Assert::isArray($verificationMaterial['timestampVerificationData']['rfc3161Timestamps']);

        $timestamps = [];
        foreach ($verificationMaterial['timestampVerificationData']['rfc3161Timestamps'] as $timestamp) {
            Assert::isArray($timestamp);
            Assert::keyExists($timestamp, 'signedTimestamp');
            Assert::stringNotEmpty($timestamp['signedTimestamp']);

            $decoded = base64_decode($timestamp['signedTimestamp']);
            Assert::stringNotEmpty($decoded);

            $timestamps[] = $decoded;
        }

        return $timestamps;
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
