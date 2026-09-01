<?php

declare(strict_types=1);

namespace ThePhpFoundation\UnitTest\Attestation\Verification;

use PHPUnit\Framework\TestCase;
use ThePhpFoundation\Attestation\Bundle;
use ThePhpFoundation\Attestation\FilenameWithChecksum;
use ThePhpFoundation\Attestation\FulcioSigstoreOidExtensions;
use ThePhpFoundation\Attestation\Verification\Exception\CannotVerifyMessageSignatureWithoutArtifact;
use ThePhpFoundation\Attestation\Verification\Exception\CertificateIdentityMismatch;
use ThePhpFoundation\Attestation\Verification\Exception\DigestMismatch;
use ThePhpFoundation\Attestation\Verification\Exception\IssuerCertificateVerificationFailed;
use ThePhpFoundation\Attestation\Verification\Exception\MismatchingExtensionValues;
use ThePhpFoundation\Attestation\Verification\Exception\NoIssuerCertificateInTrustedRoot;
use ThePhpFoundation\Attestation\Verification\Exception\SignatureVerificationFailed;
use ThePhpFoundation\Attestation\Verification\Exception\TransparencyLogEntryContentMismatch;
use ThePhpFoundation\Attestation\Verification\Exception\UntrustedCertificateTransparencyLogKey;
use ThePhpFoundation\Attestation\Verification\VerifyBundleWithOpenSsl;
use Webmozart\Assert\Assert;

use function base64_decode;
use function base64_encode;
use function chr;
use function file_get_contents;
use function json_decode;
use function ord;
use function strlen;
use function substr;

/** @covers \ThePhpFoundation\Attestation\Verification\VerifyBundleWithOpenSsl */
class VerifyBundleWithOpenSslTest extends TestCase
{
    private const BUNDLE_FIXTURE                           = __DIR__ . '/../../fixture/bundle.json';
    private const PIE_PHAR                                 = __DIR__ . '/../../fixture/pie.phar';
    private const CERTIFICATE_IDENTITY                     = 'https://github.com/php/pie/.github/workflows/build-phar.yml@refs/tags/1.2.0';
    private const MESSAGE_SIGNATURE_BUNDLE_FIXTURE         = __DIR__ . '/../../fixture/message-signature-bundle.json';
    private const MESSAGE_SIGNATURE_ARTIFACT               = __DIR__ . '/../../fixture/message-signature-artifact.txt';
    private const MESSAGE_SIGNATURE_ARTIFACT_DIGEST        = 'a0cfc71271d6e278e57cd332ff957c3f7043fdda354c4cbb190a30d56efa01bf';
    private const MESSAGE_SIGNATURE_CERTIFICATE_IDENTITY   = 'https://github.com/sigstore-conformance/extremely-dangerous-public-oidc-beacon/.github/workflows/extremely-dangerous-oidc-beacon.yml@refs/heads/main';
    private const WRONG_HASHEDREKORD_ARTIFACT_FIXTURE      = __DIR__ . '/../../fixture/wrong-hashedrekord-artifact-fail.json';
    private const WRONG_HASHEDREKORD_ENTRY_FIXTURE         = __DIR__ . '/../../fixture/wrong-hashedrekord-entry-fail.json';
    private const WRONG_HASHEDREKORD_CERT_AND_SIG_FIXTURE  = __DIR__ . '/../../fixture/wrong-hashedrekord-cert-and-sig-fail.json';
    private const DSSE_MISMATCH_ENVELOPE_FIXTURE           = __DIR__ . '/../../fixture/dsse-mismatch-envelope-fail.json';
    private const DSSE_MISMATCH_SIG_FIXTURE                = __DIR__ . '/../../fixture/dsse-mismatch-sig-fail.json';
    private const TLOG_KEY_VALIDITY_BUNDLE_FIXTURE         = __DIR__ . '/../../fixture/trust-root-tlog-validity-end-inclusive.json';
    private const TLOG_KEY_VALIDITY_TRUSTED_ROOT_FIXTURE   = __DIR__ . '/../../fixture/trust-root-tlog-validity-end-inclusive-trusted-root.json';
    private const INTOTO_LOG_ENTRY_MISMATCH_BUNDLE_FIXTURE = __DIR__ . '/../../fixture/intoto-log-entry-mismatch-fail.json';
    private const INTOTO_LOG_ENTRY_MISMATCH_TRUSTED_ROOT   = __DIR__ . '/../../fixture/intoto-log-entry-mismatch-fail-trusted-root.json';
    private const INTOTO_LOG_ENTRY_MISMATCH_ARTIFACT       = __DIR__ . '/../../fixture/intoto-log-entry-mismatch-fail-artifact.txt';
    private const INVALID_CT_KEY_FIXTURE                   = __DIR__ . '/../../fixture/invalid-ct-key-fail.json';
    private const INVALID_CT_KEY_TRUSTED_ROOT              = __DIR__ . '/../../fixture/invalid-ct-key-fail-trusted-root.json';
    private const TSA_VALIDITY_BUNDLE_FIXTURE              = __DIR__ . '/../../fixture/trust-root-tsa-validity-end-inclusive.json';
    private const TSA_VALIDITY_TRUSTED_ROOT_FIXTURE        = __DIR__ . '/../../fixture/trust-root-tsa-validity-end-inclusive-trusted-root.json';
    private const SCT_WITH_EXTENSIONS_BUNDLE_FIXTURE       = __DIR__ . '/../../fixture/bundle-with-sct-with-extensions.json';
    private const SCT_WITH_EXTENSIONS_TRUSTED_ROOT_FIXTURE = __DIR__ . '/../../fixture/bundle-with-sct-with-extensions-trusted-root.json';

    private VerifyBundleWithOpenSsl $verifier;

    public function setUp(): void
    {
        $this->verifier = VerifyBundleWithOpenSsl::factory();
    }

    /** @return non-empty-list<Bundle> */
    private function loadFixtureBundle(string $path): array
    {
        $contents = file_get_contents($path);
        Assert::stringNotEmpty($contents);

        /** @var array<array-key, mixed> $decoded */
        $decoded = json_decode($contents, true);

        return [Bundle::fromBundle($decoded)];
    }

    /** @return non-empty-list<Bundle> */
    private function loadMessageSignatureFixtureBundleWithTamperedSignature(): array
    {
        $contents = file_get_contents(self::MESSAGE_SIGNATURE_BUNDLE_FIXTURE);
        Assert::stringNotEmpty($contents);

        /** @var array<array-key, mixed> $decoded */
        $decoded = json_decode($contents, true);

        Assert::isArray($decoded['messageSignature']);
        Assert::stringNotEmpty($decoded['messageSignature']['signature']);

        $signatureBytes = base64_decode($decoded['messageSignature']['signature']);
        Assert::stringNotEmpty($signatureBytes);

        // Flip the final byte, corrupting the signature value whilst keeping the DER structure intact.
        $lastByte               = ord($signatureBytes[strlen($signatureBytes) - 1]);
        $tamperedSignatureBytes = substr($signatureBytes, 0, -1) . chr($lastByte ^ 0xFF);

        $decoded['messageSignature']['signature'] = base64_encode($tamperedSignatureBytes);

        return [Bundle::fromBundle($decoded)];
    }

    public function testSuccessfulVerification(): void
    {
        $this->expectNotToPerformAssertions();
        $this->verifier->verify(
            $this->loadFixtureBundle(self::BUNDLE_FIXTURE),
            FilenameWithChecksum::fromFilename(self::PIE_PHAR),
            'pie.phar',
            [
                FulcioSigstoreOidExtensions::ISSUER_V2 => 'https://token.actions.githubusercontent.com',
                FulcioSigstoreOidExtensions::SOURCE_REPOSITORY_URI => 'https://github.com/php/pie',
                FulcioSigstoreOidExtensions::SOURCE_REPOSITORY_OWNER_URI => 'https://github.com/php',
            ],
            self::CERTIFICATE_IDENTITY,
        );
    }

    public function testSuccessfulVerificationOfAMessageSignatureBundle(): void
    {
        $this->expectNotToPerformAssertions();
        $this->verifier->verify(
            $this->loadFixtureBundle(self::MESSAGE_SIGNATURE_BUNDLE_FIXTURE),
            FilenameWithChecksum::fromFilename(self::MESSAGE_SIGNATURE_ARTIFACT),
            'message-signature-artifact.txt',
            [],
            self::MESSAGE_SIGNATURE_CERTIFICATE_IDENTITY,
        );
    }

    public function testSuccessfulVerificationOfAnEd25519CheckpointedTransparencyLogEntry(): void
    {
        $verifier = VerifyBundleWithOpenSsl::withTrustedRootFile(self::SCT_WITH_EXTENSIONS_TRUSTED_ROOT_FIXTURE);

        $this->expectNotToPerformAssertions();
        $verifier->verify(
            $this->loadFixtureBundle(self::SCT_WITH_EXTENSIONS_BUNDLE_FIXTURE),
            FilenameWithChecksum::fromFilename(self::MESSAGE_SIGNATURE_ARTIFACT),
            'message-signature-artifact.txt',
            [],
            self::MESSAGE_SIGNATURE_CERTIFICATE_IDENTITY,
        );
    }

    public function testSuccessfulVerificationWhenIntegratedTimeIsExactlyAtTheTransparencyLogKeysValidityEnd(): void
    {
        $verifier = VerifyBundleWithOpenSsl::withTrustedRootFile(self::TLOG_KEY_VALIDITY_TRUSTED_ROOT_FIXTURE);

        $this->expectNotToPerformAssertions();
        $verifier->verify(
            $this->loadFixtureBundle(self::TLOG_KEY_VALIDITY_BUNDLE_FIXTURE),
            FilenameWithChecksum::fromFilename(self::MESSAGE_SIGNATURE_ARTIFACT),
            'message-signature-artifact.txt',
            [],
            self::MESSAGE_SIGNATURE_CERTIFICATE_IDENTITY,
        );
    }

    public function testRejectsAnIntotoEntryWithAMismatchedSignature(): void
    {
        $verifier = VerifyBundleWithOpenSsl::withTrustedRootFile(self::INTOTO_LOG_ENTRY_MISMATCH_TRUSTED_ROOT);

        $this->expectException(TransparencyLogEntryContentMismatch::class);
        $verifier->verify(
            $this->loadFixtureBundle(self::INTOTO_LOG_ENTRY_MISMATCH_BUNDLE_FIXTURE),
            FilenameWithChecksum::fromFilename(self::INTOTO_LOG_ENTRY_MISMATCH_ARTIFACT),
            'intoto-log-entry-mismatch-fail-artifact.txt',
            [],
            self::MESSAGE_SIGNATURE_CERTIFICATE_IDENTITY,
        );
    }

    public function testRejectsACertificateWhoseSignedCertificateTimestampReferencesAnUntrustedCtLog(): void
    {
        $verifier = VerifyBundleWithOpenSsl::withTrustedRootFile(self::INVALID_CT_KEY_TRUSTED_ROOT);

        $this->expectException(UntrustedCertificateTransparencyLogKey::class);
        $verifier->verify(
            $this->loadFixtureBundle(self::INVALID_CT_KEY_FIXTURE),
            FilenameWithChecksum::fromFilename(self::MESSAGE_SIGNATURE_ARTIFACT),
            'message-signature-artifact.txt',
            [],
            self::MESSAGE_SIGNATURE_CERTIFICATE_IDENTITY,
        );
    }

    public function testSuccessfulVerificationWhenRfc3161TimestampIsExactlyAtTheTimestampAuthoritysValidityEnd(): void
    {
        $verifier = VerifyBundleWithOpenSsl::withTrustedRootFile(self::TSA_VALIDITY_TRUSTED_ROOT_FIXTURE);

        $this->expectNotToPerformAssertions();
        $verifier->verify(
            $this->loadFixtureBundle(self::TSA_VALIDITY_BUNDLE_FIXTURE),
            FilenameWithChecksum::fromFilename(self::MESSAGE_SIGNATURE_ARTIFACT),
            'message-signature-artifact.txt',
            [],
            self::MESSAGE_SIGNATURE_CERTIFICATE_IDENTITY,
        );
    }

    public function testMessageSignatureBundleCannotBeVerifiedWithoutTheRealArtifact(): void
    {
        $this->expectException(CannotVerifyMessageSignatureWithoutArtifact::class);
        $this->verifier->verify(
            $this->loadFixtureBundle(self::MESSAGE_SIGNATURE_BUNDLE_FIXTURE),
            FilenameWithChecksum::fromFilenameAndChecksum(
                'sha256:' . self::MESSAGE_SIGNATURE_ARTIFACT_DIGEST,
                self::MESSAGE_SIGNATURE_ARTIFACT_DIGEST,
            ),
            'message-signature-artifact.txt',
            [],
            self::MESSAGE_SIGNATURE_CERTIFICATE_IDENTITY,
        );
    }

    public function testMessageSignatureVerificationFailedForTamperedSignature(): void
    {
        $this->expectException(TransparencyLogEntryContentMismatch::class);
        $this->verifier->verify(
            $this->loadMessageSignatureFixtureBundleWithTamperedSignature(),
            FilenameWithChecksum::fromFilename(self::MESSAGE_SIGNATURE_ARTIFACT),
            'message-signature-artifact.txt',
            [],
            self::MESSAGE_SIGNATURE_CERTIFICATE_IDENTITY,
        );
    }

    public function testMessageSignatureDigestMismatch(): void
    {
        $this->expectException(DigestMismatch::class);
        $this->verifier->verify(
            $this->loadFixtureBundle(self::MESSAGE_SIGNATURE_BUNDLE_FIXTURE),
            FilenameWithChecksum::fromFilename(self::PIE_PHAR),
            'message-signature-artifact.txt',
            [],
            self::MESSAGE_SIGNATURE_CERTIFICATE_IDENTITY,
        );
    }

    public function testRejectsBundleWhereTheHashedRekordEntryRecordsAWrongArtifactDigest(): void
    {
        $this->expectException(DigestMismatch::class);
        $this->verifier->verify(
            $this->loadFixtureBundle(self::WRONG_HASHEDREKORD_ARTIFACT_FIXTURE),
            FilenameWithChecksum::fromFilename(self::MESSAGE_SIGNATURE_ARTIFACT),
            'message-signature-artifact.txt',
            [],
            self::MESSAGE_SIGNATURE_CERTIFICATE_IDENTITY,
        );
    }

    public function testRejectsBundleWhereTheHashedRekordEntryIsForACompletelyDifferentArtifact(): void
    {
        $this->expectException(DigestMismatch::class);
        $this->verifier->verify(
            $this->loadFixtureBundle(self::WRONG_HASHEDREKORD_ENTRY_FIXTURE),
            FilenameWithChecksum::fromFilename(self::MESSAGE_SIGNATURE_ARTIFACT),
            'message-signature-artifact.txt',
            [],
            self::MESSAGE_SIGNATURE_CERTIFICATE_IDENTITY,
        );
    }

    public function testRejectsBundleWhereTheHashedRekordEntryRecordsAWrongCertificateAndSignature(): void
    {
        $this->expectException(TransparencyLogEntryContentMismatch::class);
        $this->verifier->verify(
            $this->loadFixtureBundle(self::WRONG_HASHEDREKORD_CERT_AND_SIG_FIXTURE),
            FilenameWithChecksum::fromFilename(self::MESSAGE_SIGNATURE_ARTIFACT),
            'message-signature-artifact.txt',
            [],
            self::MESSAGE_SIGNATURE_CERTIFICATE_IDENTITY,
        );
    }

    public function testRejectsBundleWhereTheDsseEntryDoesNotMatchTheEnvelope(): void
    {
        $this->expectException(DigestMismatch::class);
        $this->verifier->verify(
            $this->loadFixtureBundle(self::DSSE_MISMATCH_ENVELOPE_FIXTURE),
            FilenameWithChecksum::fromFilename(self::MESSAGE_SIGNATURE_ARTIFACT),
            'message-signature-artifact.txt',
            [],
            self::MESSAGE_SIGNATURE_CERTIFICATE_IDENTITY,
        );
    }

    public function testRejectsBundleWhereTheDsseEntryRecordsAWrongSignature(): void
    {
        $this->expectException(TransparencyLogEntryContentMismatch::class);
        $this->verifier->verify(
            $this->loadFixtureBundle(self::DSSE_MISMATCH_SIG_FIXTURE),
            FilenameWithChecksum::fromFilename(self::MESSAGE_SIGNATURE_ARTIFACT),
            'message-signature-artifact.txt',
            [],
            self::MESSAGE_SIGNATURE_CERTIFICATE_IDENTITY,
        );
    }

    public function testMismatchingExtensionClaimsAreRejected(): void
    {
        $this->expectException(MismatchingExtensionValues::class);
        $this->verifier->verify(
            $this->loadFixtureBundle(self::BUNDLE_FIXTURE),
            FilenameWithChecksum::fromFilename(self::PIE_PHAR),
            'pie.phar',
            [
                FulcioSigstoreOidExtensions::ISSUER_V2 => 'https://token.actions.githubusercontent.com',
                FulcioSigstoreOidExtensions::SOURCE_REPOSITORY_URI => 'https://github.com/php/pie',
                FulcioSigstoreOidExtensions::SOURCE_REPOSITORY_OWNER_URI => 'https://github.com/asgrim',
            ],
            self::CERTIFICATE_IDENTITY,
        );
    }

    public function testCertificateIdentityMismatchIsRejected(): void
    {
        $this->expectException(CertificateIdentityMismatch::class);
        $this->verifier->verify(
            $this->loadFixtureBundle(self::BUNDLE_FIXTURE),
            FilenameWithChecksum::fromFilename(self::PIE_PHAR),
            'pie.phar',
            [
                FulcioSigstoreOidExtensions::ISSUER_V2 => 'https://token.actions.githubusercontent.com',
                FulcioSigstoreOidExtensions::SOURCE_REPOSITORY_URI => 'https://github.com/php/pie',
                FulcioSigstoreOidExtensions::SOURCE_REPOSITORY_OWNER_URI => 'https://github.com/php',
            ],
            'https://github.com/some-other-org/some-other-repo/.github/workflows/build.yml@refs/heads/main',
        );
    }

    public function testCertificateWasNotVerifiedFromTrustedRoot(): void
    {
        $this->expectException(IssuerCertificateVerificationFailed::class);
        self::markTestIncomplete();
    }

    public function testCertificateWasNotFoundInAnyTrustedRoot(): void
    {
        $this->expectException(NoIssuerCertificateInTrustedRoot::class);
        self::markTestIncomplete();
    }

    public function testDsseEnvelopeSignatureVerificationFailed(): void
    {
        $this->expectException(SignatureVerificationFailed::class);
        self::markTestIncomplete();
    }

    public function testDigestMismatchInAttestation(): void
    {
        $this->expectException(DigestMismatch::class);
        self::markTestIncomplete();
    }
}
