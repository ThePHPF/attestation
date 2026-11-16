<?php

declare(strict_types=1);

namespace ThePhpFoundation\UnitTest\Attestation\Verification\Assertion;

use PHPUnit\Framework\TestCase;
use ThePhpFoundation\Attestation\Bundle;
use ThePhpFoundation\Attestation\FilenameWithChecksum;
use ThePhpFoundation\Attestation\Verification\Assertion\PredicateType;
use ThePhpFoundation\Attestation\Verification\Exception\PredicateTypeMismatch;
use Webmozart\Assert\Assert;

use function file_get_contents;
use function json_decode;

/** @covers \ThePhpFoundation\Attestation\Verification\Assertion\PredicateType */
final class PredicateTypeTest extends TestCase
{
    private const BUNDLE_FIXTURE                   = __DIR__ . '/../../../fixture/bundle.json';
    private const NO_PREDICATE_TYPE_BUNDLE_FIXTURE = __DIR__ . '/../../../fixture/certificate-chain-bundle.json';
    private const MESSAGE_SIGNATURE_BUNDLE_FIXTURE = __DIR__ . '/../../../fixture/message-signature-bundle.json';

    private static function bundle(string $path): Bundle
    {
        $contents = file_get_contents($path);
        Assert::stringNotEmpty($contents);

        /** @var array<array-key, mixed> $decoded */
        $decoded = json_decode($contents, true);

        return Bundle::fromBundle($decoded);
    }

    public function testAcceptsAMatchingPredicateType(): void
    {
        $check = new PredicateType('https://slsa.dev/provenance/v1');

        $this->expectNotToPerformAssertions();
        $check->assert(FilenameWithChecksum::fromFilenameAndChecksum('irrelevant', 'irrelevant'), 0, self::bundle(self::BUNDLE_FIXTURE));
    }

    public function testRejectsAMismatchingPredicateType(): void
    {
        $check = new PredicateType('https://in-toto.io/attestation/release/v0.1');

        $this->expectException(PredicateTypeMismatch::class);
        $check->assert(FilenameWithChecksum::fromFilenameAndChecksum('irrelevant', 'irrelevant'), 0, self::bundle(self::BUNDLE_FIXTURE));
    }

    public function testRejectsAStatementWithoutAPredicateType(): void
    {
        $check = new PredicateType('https://slsa.dev/provenance/v1');

        $this->expectException(PredicateTypeMismatch::class);
        $check->assert(FilenameWithChecksum::fromFilenameAndChecksum('irrelevant', 'irrelevant'), 0, self::bundle(self::NO_PREDICATE_TYPE_BUNDLE_FIXTURE));
    }

    public function testIgnoresMessageSignatureBundlesAsTheyHaveNoPredicate(): void
    {
        $check = new PredicateType('https://slsa.dev/provenance/v1');

        $this->expectNotToPerformAssertions();
        $check->assert(FilenameWithChecksum::fromFilenameAndChecksum('irrelevant', 'irrelevant'), 0, self::bundle(self::MESSAGE_SIGNATURE_BUNDLE_FIXTURE));
    }
}
