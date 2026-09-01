<?php

declare(strict_types=1);

namespace ThePhpFoundation\Attestation\Verification;

use ThePhpFoundation\Attestation\DsseEnvelope;
use ThePhpFoundation\Attestation\FilenameWithChecksum;
use ThePhpFoundation\Attestation\MessageSignature;
use ThePhpFoundation\Attestation\PemCertificate;
use ThePhpFoundation\Attestation\Verification\Assertion\BundleMediaTypeIsSupported;
use ThePhpFoundation\Attestation\Verification\Assertion\CertificateExtensionClaims;
use ThePhpFoundation\Attestation\Verification\Assertion\CertificateHasATrustedSignedCertificateTimestamp;
use ThePhpFoundation\Attestation\Verification\Assertion\CertificateIdentity;
use ThePhpFoundation\Attestation\Verification\Assertion\CertificateSignedByTrustedRoot;
use ThePhpFoundation\Attestation\Verification\Assertion\Rfc3161TimestampsAreValid;
use ThePhpFoundation\Attestation\Verification\Assertion\TransparencyLogEntriesAreWithinCertificateValidity;
use ThePhpFoundation\Attestation\Verification\Assertion\TransparencyLogEntriesAreWithinTransparencyLogKeyValidity;
use ThePhpFoundation\Attestation\Verification\Assertion\TransparencyLogEntriesHaveValidCheckpoints;
use ThePhpFoundation\Attestation\Verification\Assertion\TransparencyLogEntriesHaveValidInclusionProof;
use ThePhpFoundation\Attestation\Verification\Assertion\TransparencyLogEntriesHaveValidLogIndex;
use ThePhpFoundation\Attestation\Verification\Assertion\TransparencyLogEntriesHaveValidSignedEntryTimestamps;
use ThePhpFoundation\Attestation\Verification\Assertion\TransparencyLogEntriesMatchBundleContent;
use ThePhpFoundation\Attestation\Verification\Assertion\VerifyBundleCheck;
use ThePhpFoundation\Attestation\Verification\Exception\CannotVerifyMessageSignatureWithoutArtifact;
use ThePhpFoundation\Attestation\Verification\Exception\DigestMismatch;
use ThePhpFoundation\Attestation\Verification\Exception\InvalidSubjectDefinition;
use ThePhpFoundation\Attestation\Verification\Exception\NoOpenSsl;
use ThePhpFoundation\Attestation\Verification\Exception\SignatureVerificationFailed;
use ThePhpFoundation\Attestation\Verification\Exception\UnsupportedBundleContent;
use Webmozart\Assert\Assert;

use function array_key_exists;
use function count;
use function extension_loaded;
use function file_get_contents;
use function hash_equals;
use function is_array;
use function is_readable;
use function is_string;
use function json_decode;
use function openssl_pkey_get_public;
use function openssl_verify;

use const OPENSSL_ALGO_SHA256;

class VerifyBundleWithOpenSsl implements VerifyBundle
{
    public const TRUSTED_ROOT_FILE_PATH = __DIR__ . '/../../resources/trusted-root.jsonl';

    /** @var list<VerifyBundleCheck> */
    private array $checks;

    /** @param list<VerifyBundleCheck> $checks */
    public function __construct(array $checks)
    {
        $this->checks = $checks;
    }

    public static function factory(): self
    {
        return self::withTrustedRootFile(self::TRUSTED_ROOT_FILE_PATH);
    }

    /** @param non-empty-string $trustedRootFilePath */
    public static function withTrustedRootFile(string $trustedRootFilePath): self
    {
        return new self(self::defaultChecks(new TrustedRoot($trustedRootFilePath)));
    }

    /** @return list<VerifyBundleCheck> */
    private static function defaultChecks(TrustedRoot $trustedRoot): array
    {
        return [
            new BundleMediaTypeIsSupported(),
            new TransparencyLogEntriesHaveValidLogIndex(),
            new TransparencyLogEntriesAreWithinCertificateValidity(),
            new TransparencyLogEntriesAreWithinTransparencyLogKeyValidity($trustedRoot),
            new Rfc3161TimestampsAreValid($trustedRoot),
            new TransparencyLogEntriesHaveValidInclusionProof(),
            new TransparencyLogEntriesHaveValidCheckpoints($trustedRoot),
            new TransparencyLogEntriesHaveValidSignedEntryTimestamps($trustedRoot),
            new TransparencyLogEntriesMatchBundleContent(),
            new CertificateSignedByTrustedRoot($trustedRoot),
            new CertificateHasATrustedSignedCertificateTimestamp($trustedRoot),
        ];
    }

    /** @inheritDoc */
    public function verify(
        array $bundles,
        FilenameWithChecksum $file,
        ?string $expectedSubjectName,
        array $extensionsToVerify,
        string $expectedCertificateIdentity
    ): void {
        foreach ($bundles as $bundleIndex => $bundle) {
            /**
             * Useful references. Whilst we don't do the full verification that
             * `gh attestation verify` would (since we don't want to re-invent
             * the wheel), we can do some basic check of the DSSE Envelope.
             * We'll check the payload digest matches our expectation, and
             * verify the signature with the certificate.
             *
             *  - https://github.com/cli/cli/blob/234d2effd545fb9d72ea77aa648caa499aecaa6e/pkg/cmd/attestation/verify/verify.go#L225-L256
             *  - https://docs.sigstore.dev/logging/verify-release/
             *  - https://github.com/secure-systems-lab/dsse/blob/master/protocol.md#protocol
             */
            foreach ($this->checks as $check) {
                $check->assert($file, $bundleIndex, $bundle);
            }

            (new CertificateExtensionClaims($extensionsToVerify))->assert($file, $bundleIndex, $bundle);

            (new CertificateIdentity($expectedCertificateIdentity))->assert($file, $bundleIndex, $bundle);

            if ($bundle->content() instanceof DsseEnvelope) {
                $this->assertDigestFromAttestationMatchesActual($file, $bundle->content());
                $this->verifyDsseEnvelopeSignature($bundleIndex, $bundle->certificate(), $bundle->content());
            } elseif ($bundle->content() instanceof MessageSignature) {
                $this->assertDigestFromMessageSignatureMatchesActual($file, $bundle->content());
                $this->verifyMessageSignature($bundleIndex, $file, $bundle->certificate(), $bundle->content());
            } else {
                throw UnsupportedBundleContent::new();
            }
        }
    }

    private function verifyDsseEnvelopeSignature(int $bundleIndex, PemCertificate $certificate, DsseEnvelope $envelope): void
    {
        if (! extension_loaded('openssl')) {
            throw NoOpenssl::new();
        }

        $publicKey = openssl_pkey_get_public($certificate->decoratedCertificate());
        Assert::notFalse($publicKey);

        if (
            openssl_verify(
                $envelope->preAuthenticationEncoding(),
                $envelope->signature(),
                $publicKey,
                OPENSSL_ALGO_SHA256,
            ) !== 1
        ) {
            throw SignatureVerificationFailed::forIndex($bundleIndex);
        }
    }

    /**
     * This requires the artifact on disk to verify the signature. A digest-only verification is specifically not
     * supported, as there's nothing to verify against.
     */
    private function verifyMessageSignature(int $bundleIndex, FilenameWithChecksum $file, PemCertificate $certificate, MessageSignature $content): void
    {
        if (! extension_loaded('openssl')) {
            throw NoOpenssl::new();
        }

        if (! is_readable($file->filename())) {
            throw CannotVerifyMessageSignatureWithoutArtifact::new();
        }

        $artifactContents = file_get_contents($file->filename());
        Assert::stringNotEmpty($artifactContents);

        $publicKey = openssl_pkey_get_public($certificate->decoratedCertificate());
        Assert::notFalse($publicKey);

        if (
            openssl_verify(
                $artifactContents,
                $content->signature(),
                $publicKey,
                OPENSSL_ALGO_SHA256,
            ) !== 1
        ) {
            throw SignatureVerificationFailed::forIndex($bundleIndex);
        }
    }

    private function assertDigestFromMessageSignatureMatchesActual(FilenameWithChecksum $file, MessageSignature $content): void
    {
        $expected = $file->checksum();
        $actual   = $content->digestHex();
        if (! hash_equals($expected, $actual)) {
            throw DigestMismatch::fromChecksumMismatch($expected, $actual);
        }
    }

    private function assertDigestFromAttestationMatchesActual(FilenameWithChecksum $file, DsseEnvelope $envelope): void
    {
        /** @var mixed $decodedPayload */
        $decodedPayload = json_decode($envelope->payload(), true);

        if (
            ! is_array($decodedPayload)
            || ! array_key_exists('subject', $decodedPayload)
            || ! is_array($decodedPayload['subject'])
            || count($decodedPayload['subject']) !== 1
            || ! array_key_exists(0, $decodedPayload['subject'])
            || ! is_array($decodedPayload['subject'][0])
            || ! array_key_exists('name', $decodedPayload['subject'][0])
            || ! array_key_exists('digest', $decodedPayload['subject'][0])
            || ! is_array($decodedPayload['subject'][0]['digest'])
            || ! array_key_exists('sha256', $decodedPayload['subject'][0]['digest'])
            || ! is_string($decodedPayload['subject'][0]['digest']['sha256'])
            || $decodedPayload['subject'][0]['digest']['sha256'] === ''
        ) {
            throw InvalidSubjectDefinition::new();
        }

        $expected = $file->checksum();
        $actual   = $decodedPayload['subject'][0]['digest']['sha256'];
        if (! hash_equals($expected, $actual)) {
            throw DigestMismatch::fromChecksumMismatch($expected, $actual);
        }
    }
}
