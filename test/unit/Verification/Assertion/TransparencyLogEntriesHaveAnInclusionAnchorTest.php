<?php

declare(strict_types=1);

namespace ThePhpFoundation\UnitTest\Attestation\Verification\Assertion;

use PHPUnit\Framework\TestCase;
use ThePhpFoundation\Attestation\Bundle;
use ThePhpFoundation\Attestation\FilenameWithChecksum;
use ThePhpFoundation\Attestation\Verification\Assertion\TransparencyLogEntriesHaveAnInclusionAnchor;
use ThePhpFoundation\Attestation\Verification\Exception\MissingTransparencyLogInclusionAnchor;
use Webmozart\Assert\Assert;

use function file_get_contents;
use function json_decode;

/** @covers \ThePhpFoundation\Attestation\Verification\Assertion\TransparencyLogEntriesHaveAnInclusionAnchor */
final class TransparencyLogEntriesHaveAnInclusionAnchorTest extends TestCase
{
    private const BUNDLE_FIXTURE = __DIR__ . '/../../../fixture/bundle.json';

    /** @return array<array-key, mixed> */
    private static function decodeFixtureBundle(): array
    {
        $contents = file_get_contents(self::BUNDLE_FIXTURE);
        Assert::stringNotEmpty($contents);

        /** @var array<array-key, mixed> $decoded */
        $decoded = json_decode($contents, true);

        return $decoded;
    }

    private static function assertOnFirstBundle(Bundle $bundle): void
    {
        $check = new TransparencyLogEntriesHaveAnInclusionAnchor();
        $check->assert(FilenameWithChecksum::fromFilenameAndChecksum('irrelevant', 'irrelevant'), 0, $bundle);
    }

    public function testAcceptsAnEntryWithBothASignedEntryTimestampAndACheckpoint(): void
    {
        $this->expectNotToPerformAssertions();
        self::assertOnFirstBundle(Bundle::fromBundle(self::decodeFixtureBundle()));
    }

    /**
     * @param array<array-key, mixed> $decoded
     *
     * @return array<array-key, mixed>
     */
    private static function removeCheckpoint(array $decoded): array
    {
        Assert::isArray($decoded['verificationMaterial']);
        Assert::isArray($decoded['verificationMaterial']['tlogEntries']);
        Assert::isArray($decoded['verificationMaterial']['tlogEntries'][0]);
        Assert::isArray($decoded['verificationMaterial']['tlogEntries'][0]['inclusionProof']);

        unset($decoded['verificationMaterial']['tlogEntries'][0]['inclusionProof']['checkpoint']);

        return $decoded;
    }

    /**
     * @param array<array-key, mixed> $decoded
     *
     * @return array<array-key, mixed>
     */
    private static function removeSignedEntryTimestamp(array $decoded): array
    {
        Assert::isArray($decoded['verificationMaterial']);
        Assert::isArray($decoded['verificationMaterial']['tlogEntries']);
        Assert::isArray($decoded['verificationMaterial']['tlogEntries'][0]);

        unset($decoded['verificationMaterial']['tlogEntries'][0]['inclusionPromise']);

        return $decoded;
    }

    public function testAcceptsAnEntryWithOnlyASignedEntryTimestamp(): void
    {
        $decoded = self::removeCheckpoint(self::decodeFixtureBundle());

        $this->expectNotToPerformAssertions();
        self::assertOnFirstBundle(Bundle::fromBundle($decoded));
    }

    public function testAcceptsAnEntryWithOnlyACheckpoint(): void
    {
        $decoded = self::removeSignedEntryTimestamp(self::decodeFixtureBundle());

        $this->expectNotToPerformAssertions();
        self::assertOnFirstBundle(Bundle::fromBundle($decoded));
    }

    public function testRejectsAnEntryWithNeitherASignedEntryTimestampNorACheckpoint(): void
    {
        $decoded = self::removeCheckpoint(self::removeSignedEntryTimestamp(self::decodeFixtureBundle()));

        $this->expectException(MissingTransparencyLogInclusionAnchor::class);
        self::assertOnFirstBundle(Bundle::fromBundle($decoded));
    }
}
