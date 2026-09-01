<?php

declare(strict_types=1);

namespace ThePhpFoundation\UnitTest\Attestation\Verification;

use PHPUnit\Framework\TestCase;
use ThePhpFoundation\Attestation\Bundle;
use ThePhpFoundation\Attestation\FilenameWithChecksum;
use ThePhpFoundation\Attestation\FulcioSigstoreOidExtensions;
use ThePhpFoundation\Attestation\Verification\Exception\CannotVerifyMessageSignatureWithoutArtifact;
use ThePhpFoundation\Attestation\Verification\VerifyBundleWithOpenSsl;
use Webmozart\Assert\Assert;

use function file_get_contents;
use function json_decode;

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
    private const TLOG_KEY_VALIDITY_BUNDLE_FIXTURE         = __DIR__ . '/../../fixture/trust-root-tlog-validity-end-inclusive.json';
    private const TLOG_KEY_VALIDITY_TRUSTED_ROOT_FIXTURE   = __DIR__ . '/../../fixture/trust-root-tlog-validity-end-inclusive-trusted-root.json';
    private const TSA_VALIDITY_BUNDLE_FIXTURE              = __DIR__ . '/../../fixture/trust-root-tsa-validity-end-inclusive.json';
    private const TSA_VALIDITY_TRUSTED_ROOT_FIXTURE        = __DIR__ . '/../../fixture/trust-root-tsa-validity-end-inclusive-trusted-root.json';
    private const SCT_WITH_EXTENSIONS_BUNDLE_FIXTURE       = __DIR__ . '/../../fixture/bundle-with-sct-with-extensions.json';
    private const SCT_WITH_EXTENSIONS_TRUSTED_ROOT_FIXTURE = __DIR__ . '/../../fixture/bundle-with-sct-with-extensions-trusted-root.json';

    /** @return non-empty-list<Bundle> */
    private function loadFixtureBundle(string $path): array
    {
        $contents = file_get_contents($path);
        Assert::stringNotEmpty($contents);

        /** @var array<array-key, mixed> $decoded */
        $decoded = json_decode($contents, true);

        return [Bundle::fromBundle($decoded)];
    }

    private static function verifierForMessageSignatureFixtures(): VerifyBundleWithOpenSsl
    {
        return VerifyBundleWithOpenSsl::factory([], self::MESSAGE_SIGNATURE_CERTIFICATE_IDENTITY);
    }

    public function testSuccessfulVerification(): void
    {
        $verifier = VerifyBundleWithOpenSsl::factory(
            [
                FulcioSigstoreOidExtensions::ISSUER_V2 => 'https://token.actions.githubusercontent.com',
                FulcioSigstoreOidExtensions::SOURCE_REPOSITORY_URI => 'https://github.com/php/pie',
                FulcioSigstoreOidExtensions::SOURCE_REPOSITORY_OWNER_URI => 'https://github.com/php',
            ],
            self::CERTIFICATE_IDENTITY,
        );

        $this->expectNotToPerformAssertions();
        $verifier->verify(
            $this->loadFixtureBundle(self::BUNDLE_FIXTURE),
            FilenameWithChecksum::fromFilename(self::PIE_PHAR),
        );
    }

    public function testSuccessfulVerificationOfAMessageSignatureBundle(): void
    {
        $this->expectNotToPerformAssertions();
        self::verifierForMessageSignatureFixtures()->verify(
            $this->loadFixtureBundle(self::MESSAGE_SIGNATURE_BUNDLE_FIXTURE),
            FilenameWithChecksum::fromFilename(self::MESSAGE_SIGNATURE_ARTIFACT),
        );
    }

    public function testSuccessfulVerificationOfAnEd25519CheckpointedTransparencyLogEntry(): void
    {
        $verifier = VerifyBundleWithOpenSsl::withTrustedRootFile(
            self::SCT_WITH_EXTENSIONS_TRUSTED_ROOT_FIXTURE,
            [],
            self::MESSAGE_SIGNATURE_CERTIFICATE_IDENTITY,
        );

        $this->expectNotToPerformAssertions();
        $verifier->verify(
            $this->loadFixtureBundle(self::SCT_WITH_EXTENSIONS_BUNDLE_FIXTURE),
            FilenameWithChecksum::fromFilename(self::MESSAGE_SIGNATURE_ARTIFACT),
        );
    }

    public function testSuccessfulVerificationWhenIntegratedTimeIsExactlyAtTheTransparencyLogKeysValidityEnd(): void
    {
        $verifier = VerifyBundleWithOpenSsl::withTrustedRootFile(
            self::TLOG_KEY_VALIDITY_TRUSTED_ROOT_FIXTURE,
            [],
            self::MESSAGE_SIGNATURE_CERTIFICATE_IDENTITY,
        );

        $this->expectNotToPerformAssertions();
        $verifier->verify(
            $this->loadFixtureBundle(self::TLOG_KEY_VALIDITY_BUNDLE_FIXTURE),
            FilenameWithChecksum::fromFilename(self::MESSAGE_SIGNATURE_ARTIFACT),
        );
    }

    public function testSuccessfulVerificationWhenRfc3161TimestampIsExactlyAtTheTimestampAuthoritysValidityEnd(): void
    {
        $verifier = VerifyBundleWithOpenSsl::withTrustedRootFile(
            self::TSA_VALIDITY_TRUSTED_ROOT_FIXTURE,
            [],
            self::MESSAGE_SIGNATURE_CERTIFICATE_IDENTITY,
        );

        $this->expectNotToPerformAssertions();
        $verifier->verify(
            $this->loadFixtureBundle(self::TSA_VALIDITY_BUNDLE_FIXTURE),
            FilenameWithChecksum::fromFilename(self::MESSAGE_SIGNATURE_ARTIFACT),
        );
    }

    public function testMessageSignatureBundleCannotBeVerifiedWithoutTheRealArtifact(): void
    {
        $this->expectException(CannotVerifyMessageSignatureWithoutArtifact::class);
        self::verifierForMessageSignatureFixtures()->verify(
            $this->loadFixtureBundle(self::MESSAGE_SIGNATURE_BUNDLE_FIXTURE),
            FilenameWithChecksum::fromFilenameAndChecksum(
                'sha256:' . self::MESSAGE_SIGNATURE_ARTIFACT_DIGEST,
                self::MESSAGE_SIGNATURE_ARTIFACT_DIGEST,
            ),
        );
    }
}
