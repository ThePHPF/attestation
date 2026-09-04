<?php

declare(strict_types=1);

namespace ThePhpFoundation\UnitTest\Attestation\Verification\Assertion;

use PHPUnit\Framework\TestCase;
use ThePhpFoundation\Attestation\Bundle;
use ThePhpFoundation\Attestation\FilenameWithChecksum;
use ThePhpFoundation\Attestation\Verification\Assertion\TransparencyLogEntriesHaveValidCheckpoints;
use ThePhpFoundation\Attestation\Verification\Exception\CheckpointKeyHintMismatch;
use ThePhpFoundation\Attestation\Verification\Exception\CheckpointRootHashMismatch;
use ThePhpFoundation\Attestation\Verification\Exception\CheckpointSignatureVerificationFailed;
use ThePhpFoundation\Attestation\Verification\TrustedRoot;
use Webmozart\Assert\Assert;

use function array_search;
use function base64_decode;
use function base64_encode;
use function chr;
use function explode;
use function file_get_contents;
use function implode;
use function json_decode;
use function ord;
use function strlen;
use function substr;

/** @covers \ThePhpFoundation\Attestation\Verification\Assertion\TransparencyLogEntriesHaveValidCheckpoints */
final class TransparencyLogEntriesHaveValidCheckpointsTest extends TestCase
{
    private const PRODUCTION_TRUSTED_ROOT = __DIR__ . '/../../../../resources/trusted-root.jsonl';

    private const INVALID_CHECKPOINT_SIGNATURE_FIXTURE = __DIR__ . '/../../../fixture/invalid-checkpoint-signature-fail.json';
    private const CHECKPOINT_BAD_KEYHINT_FIXTURE       = __DIR__ . '/../../../fixture/checkpoint-bad-keyhint-fail.json';
    private const CHECKPOINT_WRONG_ROOTHASH_FIXTURE    = __DIR__ . '/../../../fixture/checkpoint-wrong-roothash-fail.json';

    private const SCT_WITH_EXTENSIONS_BUNDLE_FIXTURE       = __DIR__ . '/../../../fixture/bundle-with-sct-with-extensions.json';
    private const SCT_WITH_EXTENSIONS_TRUSTED_ROOT_FIXTURE = __DIR__ . '/../../../fixture/bundle-with-sct-with-extensions-trusted-root.json';

    private const REKOR2_CHECKPOINT_ORIGIN_NOT_FIRST_BUNDLE_FIXTURE       = __DIR__ . '/../../../fixture/rekor2-checkpoint-origin-not-first.json';
    private const REKOR2_CHECKPOINT_ORIGIN_NOT_FIRST_TRUSTED_ROOT_FIXTURE = __DIR__ . '/../../../fixture/rekor2-checkpoint-origin-not-first-trusted-root.json';

    /** @return non-empty-list<Bundle> */
    private static function loadFixtureBundle(string $path): array
    {
        $contents = file_get_contents($path);
        Assert::stringNotEmpty($contents);

        /** @var array<array-key, mixed> $decoded */
        $decoded = json_decode($contents, true);

        return [Bundle::fromBundle($decoded)];
    }

    /** @return non-empty-list<Bundle> */
    private static function loadSctWithExtensionsFixtureBundleWithTamperedCheckpointSignature(): array
    {
        $contents = file_get_contents(self::SCT_WITH_EXTENSIONS_BUNDLE_FIXTURE);
        Assert::stringNotEmpty($contents);

        /** @var array<array-key, mixed> $decoded */
        $decoded = json_decode($contents, true);

        Assert::isArray($decoded['verificationMaterial']);
        Assert::isArray($decoded['verificationMaterial']['tlogEntries']);
        Assert::isArray($decoded['verificationMaterial']['tlogEntries'][0]);
        Assert::isArray($decoded['verificationMaterial']['tlogEntries'][0]['inclusionProof']);
        Assert::isArray($decoded['verificationMaterial']['tlogEntries'][0]['inclusionProof']['checkpoint']);
        Assert::stringNotEmpty($decoded['verificationMaterial']['tlogEntries'][0]['inclusionProof']['checkpoint']['envelope']);

        $lines          = explode("\n", $decoded['verificationMaterial']['tlogEntries'][0]['inclusionProof']['checkpoint']['envelope']);
        $blankLineIndex = array_search('', $lines, true);
        Assert::notFalse($blankLineIndex);
        Assert::keyExists($lines, $blankLineIndex + 1);

        $signatureLineParts = explode(' ', $lines[$blankLineIndex + 1], 3);
        Assert::count($signatureLineParts, 3);

        $signatureBlob = base64_decode($signatureLineParts[2]);
        Assert::stringNotEmpty($signatureBlob);

        $lastByte              = ord($signatureBlob[strlen($signatureBlob) - 1]);
        $tamperedSignature     = substr($signatureBlob, 0, -1) . chr($lastByte ^ 0xFF);
        $signatureLineParts[2] = base64_encode($tamperedSignature);

        $lines[$blankLineIndex + 1] = implode(' ', $signatureLineParts);

        $decoded['verificationMaterial']['tlogEntries'][0]['inclusionProof']['checkpoint']['envelope'] = implode("\n", $lines);

        return [Bundle::fromBundle($decoded)];
    }

    private static function assertOnFirstBundle(TransparencyLogEntriesHaveValidCheckpoints $check, Bundle $bundle): void
    {
        $check->assert(FilenameWithChecksum::fromFilenameAndChecksum('irrelevant', 'irrelevant'), 0, $bundle);
    }

    public function testAcceptsACheckpointWhereTheLogsSignatureIsNotTheFirstLine(): void
    {
        $check = new TransparencyLogEntriesHaveValidCheckpoints(new TrustedRoot(self::REKOR2_CHECKPOINT_ORIGIN_NOT_FIRST_TRUSTED_ROOT_FIXTURE));

        $this->expectNotToPerformAssertions();
        self::assertOnFirstBundle($check, self::loadFixtureBundle(self::REKOR2_CHECKPOINT_ORIGIN_NOT_FIRST_BUNDLE_FIXTURE)[0]);
    }

    public function testAcceptsAValidEd25519Checkpoint(): void
    {
        $check = new TransparencyLogEntriesHaveValidCheckpoints(new TrustedRoot(self::SCT_WITH_EXTENSIONS_TRUSTED_ROOT_FIXTURE));

        $this->expectNotToPerformAssertions();
        self::assertOnFirstBundle($check, self::loadFixtureBundle(self::SCT_WITH_EXTENSIONS_BUNDLE_FIXTURE)[0]);
    }

    public function testRejectsAnEd25519CheckpointWithATamperedSignature(): void
    {
        $check = new TransparencyLogEntriesHaveValidCheckpoints(new TrustedRoot(self::SCT_WITH_EXTENSIONS_TRUSTED_ROOT_FIXTURE));

        $this->expectException(CheckpointSignatureVerificationFailed::class);
        self::assertOnFirstBundle($check, self::loadSctWithExtensionsFixtureBundleWithTamperedCheckpointSignature()[0]);
    }

    public function testRejectsAnInvalidCheckpointSignature(): void
    {
        $check = new TransparencyLogEntriesHaveValidCheckpoints(new TrustedRoot(self::PRODUCTION_TRUSTED_ROOT));

        $this->expectException(CheckpointSignatureVerificationFailed::class);
        self::assertOnFirstBundle($check, self::loadFixtureBundle(self::INVALID_CHECKPOINT_SIGNATURE_FIXTURE)[0]);
    }

    public function testRejectsACheckpointSignatureKeyHintMismatch(): void
    {
        $check = new TransparencyLogEntriesHaveValidCheckpoints(new TrustedRoot(self::PRODUCTION_TRUSTED_ROOT));

        $this->expectException(CheckpointKeyHintMismatch::class);
        self::assertOnFirstBundle($check, self::loadFixtureBundle(self::CHECKPOINT_BAD_KEYHINT_FIXTURE)[0]);
    }

    public function testRejectsACheckpointRootHashMismatch(): void
    {
        $check = new TransparencyLogEntriesHaveValidCheckpoints(new TrustedRoot(self::PRODUCTION_TRUSTED_ROOT));

        $this->expectException(CheckpointRootHashMismatch::class);
        self::assertOnFirstBundle($check, self::loadFixtureBundle(self::CHECKPOINT_WRONG_ROOTHASH_FIXTURE)[0]);
    }
}
