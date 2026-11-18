<?php

declare(strict_types=1);

namespace ThePhpFoundation\UnitTest\Attestation\Verification\Assertion;

use PHPUnit\Framework\TestCase;
use ThePhpFoundation\Attestation\Bundle;
use ThePhpFoundation\Attestation\FilenameWithChecksum;
use ThePhpFoundation\Attestation\Verification\Assertion\ReleaseTag;
use ThePhpFoundation\Attestation\Verification\Exception\ReleaseTagMismatch;
use Webmozart\Assert\Assert;

use function file_get_contents;
use function json_decode;

/** @covers \ThePhpFoundation\Attestation\Verification\Assertion\ReleaseTag */
final class ReleaseTagTest extends TestCase
{
    private const RELEASE_BUNDLE_FIXTURE           = __DIR__ . '/../../../fixture/pie-1.5.5-release-bundle.json';
    private const PROVENANCE_BUNDLE_FIXTURE        = __DIR__ . '/../../../fixture/bundle.json';
    private const MESSAGE_SIGNATURE_BUNDLE_FIXTURE = __DIR__ . '/../../../fixture/message-signature-bundle.json';

    private static function bundle(string $path): Bundle
    {
        $contents = file_get_contents($path);
        Assert::stringNotEmpty($contents);

        /** @var array<array-key, mixed> $decoded */
        $decoded = json_decode($contents, true);

        return Bundle::fromBundle($decoded);
    }

    public function testAcceptsAMatchingReleaseTag(): void
    {
        $check = new ReleaseTag('1.5.5');

        $this->expectNotToPerformAssertions();
        $check->assert(FilenameWithChecksum::fromFilenameAndChecksum('irrelevant', 'irrelevant'), 0, self::bundle(self::RELEASE_BUNDLE_FIXTURE));
    }

    public function testRejectsAMismatchingReleaseTag(): void
    {
        $check = new ReleaseTag('1.5.4');

        $this->expectException(ReleaseTagMismatch::class);
        $check->assert(FilenameWithChecksum::fromFilenameAndChecksum('irrelevant', 'irrelevant'), 0, self::bundle(self::RELEASE_BUNDLE_FIXTURE));
    }

    public function testRejectsAStatementWithoutAReleaseTag(): void
    {
        $check = new ReleaseTag('1.5.5');

        $this->expectException(ReleaseTagMismatch::class);
        $check->assert(FilenameWithChecksum::fromFilenameAndChecksum('irrelevant', 'irrelevant'), 0, self::bundle(self::PROVENANCE_BUNDLE_FIXTURE));
    }

    public function testRejectsAMessageSignatureBundleAsItHasNoReleaseTag(): void
    {
        $check = new ReleaseTag('1.5.5');

        $this->expectException(ReleaseTagMismatch::class);
        $check->assert(FilenameWithChecksum::fromFilenameAndChecksum('irrelevant', 'irrelevant'), 0, self::bundle(self::MESSAGE_SIGNATURE_BUNDLE_FIXTURE));
    }
}
