<?php

declare(strict_types=1);

namespace ThePhpFoundation\UnitTest\Attestation\Verification\Assertion;

use PHPUnit\Framework\TestCase;
use ThePhpFoundation\Attestation\Bundle;
use ThePhpFoundation\Attestation\FilenameWithChecksum;
use ThePhpFoundation\Attestation\Verification\Assertion\SubjectDigestMatchesReleaseTag;
use ThePhpFoundation\Attestation\Verification\Exception\ReleaseTagDigestMismatch;
use Webmozart\Assert\Assert;

use function base64_encode;
use function file_get_contents;
use function json_decode;
use function json_encode;

use const JSON_THROW_ON_ERROR;

/** @covers \ThePhpFoundation\Attestation\Verification\Assertion\SubjectDigestMatchesReleaseTag */
final class SubjectDigestMatchesReleaseTagTest extends TestCase
{
    private const RELEASE_BUNDLE_FIXTURE           = __DIR__ . '/../../../fixture/pie-1.5.5-release-bundle.json';
    private const PROVENANCE_BUNDLE_FIXTURE        = __DIR__ . '/../../../fixture/bundle.json';
    private const MESSAGE_SIGNATURE_BUNDLE_FIXTURE = __DIR__ . '/../../../fixture/message-signature-bundle.json';
    private const RELEASE_TAG_SHA1                 = 'a41ca99acf93460f75a2acd830b2b8f013571e3a';
    private const RELEASE_TAG_SHA256               = '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08';

    private static function bundle(string $path): Bundle
    {
        $contents = file_get_contents($path);
        Assert::stringNotEmpty($contents);

        /** @var array<array-key, mixed> $decoded */
        $decoded = json_decode($contents, true);

        return Bundle::fromBundle($decoded);
    }

    private static function bundleWithSha256TagSubject(): Bundle
    {
        return Bundle::fromBundle([
            'mediaType' => 'application/vnd.dev.sigstore.bundle.v0.3+json',
            'verificationMaterial' => ['certificate' => ['rawBytes' => base64_encode('not a real certificate')]],
            'dsseEnvelope' => [
                'payloadType' => 'application/vnd.in-toto+json',
                'payload' => base64_encode(json_encode([
                    '_type' => 'https://in-toto.io/Statement/v1',
                    'subject' => [
                        ['uri' => 'pkg:github/php/pie@1.5.5', 'digest' => ['sha256' => self::RELEASE_TAG_SHA256]],
                    ],
                ], JSON_THROW_ON_ERROR)),
                'signatures' => [['sig' => base64_encode('not a real signature')]],
            ],
        ]);
    }

    public function testAcceptsABundleWithASubjectMatchingTheSha1ReleaseTagDigest(): void
    {
        $check = new SubjectDigestMatchesReleaseTag(self::RELEASE_TAG_SHA1);

        $this->expectNotToPerformAssertions();
        $check->assert(FilenameWithChecksum::fromFilenameAndChecksum('irrelevant', 'irrelevant'), 0, self::bundle(self::RELEASE_BUNDLE_FIXTURE));
    }

    public function testAcceptsABundleWithASubjectMatchingTheSha256ReleaseTagDigest(): void
    {
        $check = new SubjectDigestMatchesReleaseTag(self::RELEASE_TAG_SHA256);

        $this->expectNotToPerformAssertions();
        $check->assert(FilenameWithChecksum::fromFilenameAndChecksum('irrelevant', 'irrelevant'), 0, self::bundleWithSha256TagSubject());
    }

    public function testRejectsABundleWithoutASubjectMatchingTheReleaseTagDigest(): void
    {
        $check = new SubjectDigestMatchesReleaseTag('7ebc116a58d99e8cb0a24da841c7caa2b7d1e09f');

        $this->expectException(ReleaseTagDigestMismatch::class);
        $check->assert(FilenameWithChecksum::fromFilenameAndChecksum('irrelevant', 'irrelevant'), 0, self::bundle(self::RELEASE_BUNDLE_FIXTURE));
    }

    public function testRejectsAProvenanceBundleAsItHasNoReleaseTagDigest(): void
    {
        $check = new SubjectDigestMatchesReleaseTag(self::RELEASE_TAG_SHA1);

        $this->expectException(ReleaseTagDigestMismatch::class);
        $check->assert(FilenameWithChecksum::fromFilenameAndChecksum('irrelevant', 'irrelevant'), 0, self::bundle(self::PROVENANCE_BUNDLE_FIXTURE));
    }

    public function testRejectsAMessageSignatureBundleAsItHasNoSubjects(): void
    {
        $check = new SubjectDigestMatchesReleaseTag(self::RELEASE_TAG_SHA1);

        $this->expectException(ReleaseTagDigestMismatch::class);
        $check->assert(FilenameWithChecksum::fromFilenameAndChecksum('irrelevant', 'irrelevant'), 0, self::bundle(self::MESSAGE_SIGNATURE_BUNDLE_FIXTURE));
    }
}
