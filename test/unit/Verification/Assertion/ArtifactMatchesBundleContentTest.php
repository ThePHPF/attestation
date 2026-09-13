<?php

declare(strict_types=1);

namespace ThePhpFoundation\UnitTest\Attestation\Verification\Assertion;

use PHPUnit\Framework\TestCase;
use ThePhpFoundation\Attestation\Bundle;
use ThePhpFoundation\Attestation\FilenameWithChecksum;
use ThePhpFoundation\Attestation\Verification\Assertion\ArtifactMatchesBundleContent;
use ThePhpFoundation\Attestation\Verification\Exception\DigestMismatch;
use ThePhpFoundation\Attestation\Verification\Exception\InvalidSubjectDefinition;
use ThePhpFoundation\Attestation\Verification\Exception\SignatureVerificationFailed;
use Webmozart\Assert\Assert;

use function base64_decode;
use function base64_encode;
use function chr;
use function file_get_contents;
use function json_decode;
use function json_encode;
use function ord;
use function strlen;
use function substr;

/** @covers \ThePhpFoundation\Attestation\Verification\Assertion\ArtifactMatchesBundleContent */
final class ArtifactMatchesBundleContentTest extends TestCase
{
    private const BUNDLE_FIXTURE                    = __DIR__ . '/../../../fixture/bundle.json';
    private const PIE_PHAR                          = __DIR__ . '/../../../fixture/pie.phar';
    private const MESSAGE_SIGNATURE_BUNDLE_FIXTURE  = __DIR__ . '/../../../fixture/message-signature-bundle.json';
    private const MESSAGE_SIGNATURE_ARTIFACT        = __DIR__ . '/../../../fixture/message-signature-artifact.txt';
    private const MESSAGE_SIGNATURE_ARTIFACT_DIGEST = 'a0cfc71271d6e278e57cd332ff957c3f7043fdda354c4cbb190a30d56efa01bf';

    /** Real bundle for Python 3.9.14 (2022); signed with a P-384 key, but declares a SHA-256 digest. */
    private const P384_HISTORICAL_BUNDLE_FIXTURE  = __DIR__ . '/../../../fixture/python-3.9.14-historical.json';
    private const P384_HISTORICAL_ARTIFACT_DIGEST = '9201836e2c16361b2b7408680502393737d44f227333fe2e5729c7d5f6041675';

    /** @return array<array-key, mixed> */
    private static function decodedFixture(string $path): array
    {
        $contents = file_get_contents($path);
        Assert::stringNotEmpty($contents);

        /** @var array<array-key, mixed> $decoded */
        $decoded = json_decode($contents, true);

        return $decoded;
    }

    private static function bundle(string $path): Bundle
    {
        return Bundle::fromBundle(self::decodedFixture($path));
    }

    private static function tamperedSignature(string $signatureBase64): string
    {
        $signatureBytes = base64_decode($signatureBase64);
        Assert::stringNotEmpty($signatureBytes);

        $lastByte = ord($signatureBytes[strlen($signatureBytes) - 1]);

        return base64_encode(substr($signatureBytes, 0, -1) . chr($lastByte ^ 0xFF));
    }

    private static function dsseBundleWithTamperedSignature(): Bundle
    {
        $decoded = self::decodedFixture(self::BUNDLE_FIXTURE);
        Assert::isArray($decoded['dsseEnvelope']);
        Assert::isArray($decoded['dsseEnvelope']['signatures']);
        Assert::isArray($decoded['dsseEnvelope']['signatures'][0]);
        Assert::stringNotEmpty($decoded['dsseEnvelope']['signatures'][0]['sig']);

        $decoded['dsseEnvelope']['signatures'][0]['sig'] = self::tamperedSignature($decoded['dsseEnvelope']['signatures'][0]['sig']);

        return Bundle::fromBundle($decoded);
    }

    private static function messageSignatureBundleWithTamperedSignature(): Bundle
    {
        $decoded = self::decodedFixture(self::MESSAGE_SIGNATURE_BUNDLE_FIXTURE);
        Assert::isArray($decoded['messageSignature']);
        Assert::stringNotEmpty($decoded['messageSignature']['signature']);

        $decoded['messageSignature']['signature'] = self::tamperedSignature($decoded['messageSignature']['signature']);

        return Bundle::fromBundle($decoded);
    }

    private static function dsseBundleWithInvalidSubjectDefinition(): Bundle
    {
        $decoded = self::decodedFixture(self::BUNDLE_FIXTURE);
        Assert::isArray($decoded['dsseEnvelope']);

        $decoded['dsseEnvelope']['payload'] = base64_encode((string) json_encode(['notSubject' => 'invalid']));

        return Bundle::fromBundle($decoded);
    }

    private static function check(): ArtifactMatchesBundleContent
    {
        return new ArtifactMatchesBundleContent();
    }

    public function testAcceptsAValidDsseEnvelope(): void
    {
        $this->expectNotToPerformAssertions();
        self::check()->assert(FilenameWithChecksum::fromFilename(self::PIE_PHAR), 0, self::bundle(self::BUNDLE_FIXTURE));
    }

    public function testRejectsADsseEnvelopeWithAMismatchedDigest(): void
    {
        $this->expectException(DigestMismatch::class);
        self::check()->assert(FilenameWithChecksum::fromFilename(self::MESSAGE_SIGNATURE_ARTIFACT), 0, self::bundle(self::BUNDLE_FIXTURE));
    }

    public function testRejectsADsseEnvelopeWithAnInvalidSubjectDefinition(): void
    {
        $this->expectException(InvalidSubjectDefinition::class);
        self::check()->assert(FilenameWithChecksum::fromFilename(self::PIE_PHAR), 0, self::dsseBundleWithInvalidSubjectDefinition());
    }

    public function testRejectsADsseEnvelopeWithATamperedSignature(): void
    {
        $this->expectException(SignatureVerificationFailed::class);
        self::check()->assert(FilenameWithChecksum::fromFilename(self::PIE_PHAR), 0, self::dsseBundleWithTamperedSignature());
    }

    public function testAcceptsAValidMessageSignature(): void
    {
        $this->expectNotToPerformAssertions();
        self::check()->assert(
            FilenameWithChecksum::fromFilename(self::MESSAGE_SIGNATURE_ARTIFACT),
            0,
            self::bundle(self::MESSAGE_SIGNATURE_BUNDLE_FIXTURE),
        );
    }

    public function testRejectsAMessageSignatureWithAMismatchedDigest(): void
    {
        $this->expectException(DigestMismatch::class);
        self::check()->assert(FilenameWithChecksum::fromFilename(self::PIE_PHAR), 0, self::bundle(self::MESSAGE_SIGNATURE_BUNDLE_FIXTURE));
    }

    public function testRejectsAMessageSignatureWithATamperedSignature(): void
    {
        $this->expectException(SignatureVerificationFailed::class);
        self::check()->assert(
            FilenameWithChecksum::fromFilename(self::MESSAGE_SIGNATURE_ARTIFACT),
            0,
            self::messageSignatureBundleWithTamperedSignature(),
        );
    }

    public function testAcceptsAMessageSignatureVerifiedFromTheDigestAloneWhenTheRealArtifactIsUnavailable(): void
    {
        $this->expectNotToPerformAssertions();
        self::check()->assert(
            FilenameWithChecksum::fromFilenameAndChecksum(
                'sha256:' . self::MESSAGE_SIGNATURE_ARTIFACT_DIGEST,
                self::MESSAGE_SIGNATURE_ARTIFACT_DIGEST,
            ),
            0,
            self::bundle(self::MESSAGE_SIGNATURE_BUNDLE_FIXTURE),
        );
    }

    public function testAcceptsAP384MessageSignatureVerifiedFromTheDigestAloneWhenTheRealArtifactIsUnavailable(): void
    {
        $this->expectNotToPerformAssertions();
        self::check()->assert(
            FilenameWithChecksum::fromFilenameAndChecksum(
                'sha256:' . self::P384_HISTORICAL_ARTIFACT_DIGEST,
                self::P384_HISTORICAL_ARTIFACT_DIGEST,
            ),
            0,
            self::bundle(self::P384_HISTORICAL_BUNDLE_FIXTURE),
        );
    }

    public function testRejectsATamperedMessageSignatureWhenVerifiedFromTheDigestAlone(): void
    {
        $this->expectException(SignatureVerificationFailed::class);
        self::check()->assert(
            FilenameWithChecksum::fromFilenameAndChecksum(
                'sha256:' . self::MESSAGE_SIGNATURE_ARTIFACT_DIGEST,
                self::MESSAGE_SIGNATURE_ARTIFACT_DIGEST,
            ),
            0,
            self::messageSignatureBundleWithTamperedSignature(),
        );
    }
}
