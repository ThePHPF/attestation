<?php

declare(strict_types=1);

namespace ThePhpFoundation\UnitTest\Attestation\Verification\Assertion;

use PHPUnit\Framework\TestCase;
use ThePhpFoundation\Attestation\Bundle;
use ThePhpFoundation\Attestation\FilenameWithChecksum;
use ThePhpFoundation\Attestation\Verification\Assertion\TransparencyLogEntriesHaveValidSignedEntryTimestamps;
use ThePhpFoundation\Attestation\Verification\Exception\SignedEntryTimestampVerificationFailed;
use ThePhpFoundation\Attestation\Verification\TrustedRoot;
use Webmozart\Assert\Assert;

use function file_get_contents;
use function json_decode;

/** @covers \ThePhpFoundation\Attestation\Verification\Assertion\TransparencyLogEntriesHaveValidSignedEntryTimestamps */
final class TransparencyLogEntriesHaveValidSignedEntryTimestampsTest extends TestCase
{
    private const PRODUCTION_TRUSTED_ROOT = __DIR__ . '/../../../../resources/trusted-root.jsonl';

    private const BUNDLE_FIXTURE                = __DIR__ . '/../../../fixture/bundle.json';
    private const SET_INVALID_SIGNATURE_FIXTURE = __DIR__ . '/../../../fixture/set-invalid-signature-fail.json';

    private static function loadFixtureBundle(string $path): Bundle
    {
        $contents = file_get_contents($path);
        Assert::stringNotEmpty($contents);

        /** @var array<array-key, mixed> $decoded */
        $decoded = json_decode($contents, true);

        return Bundle::fromBundle($decoded);
    }

    private static function check(): TransparencyLogEntriesHaveValidSignedEntryTimestamps
    {
        return new TransparencyLogEntriesHaveValidSignedEntryTimestamps(new TrustedRoot(self::PRODUCTION_TRUSTED_ROOT));
    }

    public function testAcceptsAValidSignedEntryTimestamp(): void
    {
        $this->expectNotToPerformAssertions();
        self::check()->assert(
            FilenameWithChecksum::fromFilenameAndChecksum('irrelevant', 'irrelevant'),
            0,
            self::loadFixtureBundle(self::BUNDLE_FIXTURE),
        );
    }

    public function testRejectsAnInvalidSignedEntryTimestamp(): void
    {
        $this->expectException(SignedEntryTimestampVerificationFailed::class);
        self::check()->assert(
            FilenameWithChecksum::fromFilenameAndChecksum('irrelevant', 'irrelevant'),
            0,
            self::loadFixtureBundle(self::SET_INVALID_SIGNATURE_FIXTURE),
        );
    }
}
