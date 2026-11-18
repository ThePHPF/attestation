<?php

declare(strict_types=1);

namespace ThePhpFoundation\UnitTest\Attestation\Verification\Assertion;

use PHPUnit\Framework\TestCase;
use ThePhpFoundation\Attestation\Bundle;
use ThePhpFoundation\Attestation\FilenameWithChecksum;
use ThePhpFoundation\Attestation\Verification\Assertion\BundleHasAtLeastOneRfc3161Timestamp;
use ThePhpFoundation\Attestation\Verification\Exception\MissingTimestampEvidence;
use Webmozart\Assert\Assert;

use function file_get_contents;
use function json_decode;

/** @covers \ThePhpFoundation\Attestation\Verification\Assertion\BundleHasAtLeastOneRfc3161Timestamp */
final class BundleHasAtLeastOneRfc3161TimestampTest extends TestCase
{
    private const RELEASE_BUNDLE_FIXTURE   = __DIR__ . '/../../../fixture/pie-1.5.5-release-bundle.json';
    private const TLOG_ONLY_BUNDLE_FIXTURE = __DIR__ . '/../../../fixture/bundle.json';

    private static function bundle(string $path): Bundle
    {
        $contents = file_get_contents($path);
        Assert::stringNotEmpty($contents);

        /** @var array<array-key, mixed> $decoded */
        $decoded = json_decode($contents, true);

        return Bundle::fromBundle($decoded);
    }

    public function testAcceptsABundleWithAnRfc3161Timestamp(): void
    {
        $this->expectNotToPerformAssertions();
        (new BundleHasAtLeastOneRfc3161Timestamp())->assert(
            FilenameWithChecksum::fromFilenameAndChecksum('irrelevant', 'irrelevant'),
            0,
            self::bundle(self::RELEASE_BUNDLE_FIXTURE),
        );
    }

    public function testRejectsABundleWhoseOnlyTimestampIsATransparencyLogIntegratedTime(): void
    {
        $this->expectException(MissingTimestampEvidence::class);
        (new BundleHasAtLeastOneRfc3161Timestamp())->assert(
            FilenameWithChecksum::fromFilenameAndChecksum('irrelevant', 'irrelevant'),
            0,
            self::bundle(self::TLOG_ONLY_BUNDLE_FIXTURE),
        );
    }
}
