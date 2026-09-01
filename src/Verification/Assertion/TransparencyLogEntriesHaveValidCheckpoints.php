<?php

declare(strict_types=1);

namespace ThePhpFoundation\Attestation\Verification\Assertion;

use ThePhpFoundation\Attestation\Bundle;
use ThePhpFoundation\Attestation\FilenameWithChecksum;
use ThePhpFoundation\Attestation\Verification\Exception\CheckpointKeyHintMismatch;
use ThePhpFoundation\Attestation\Verification\Exception\CheckpointRootHashMismatch;
use ThePhpFoundation\Attestation\Verification\Exception\CheckpointSignatureVerificationFailed;
use ThePhpFoundation\Attestation\Verification\Exception\InvalidCheckpointFormat;
use ThePhpFoundation\Attestation\Verification\TransparencyLogSignature;
use ThePhpFoundation\Attestation\Verification\TrustedRoot;
use Webmozart\Assert\Assert;

use function array_search;
use function array_slice;
use function base64_decode;
use function count;
use function explode;
use function hash_equals;
use function implode;
use function strlen;
use function substr;

/**
 * @link https://github.com/sigstore/rekor/blob/main/pkg/util/checkpoint.go
 * @link https://github.com/sigstore/rekor/blob/main/pkg/util/signed_note.go
 */
final class TransparencyLogEntriesHaveValidCheckpoints implements VerifyBundleCheck
{
    public function __construct(private TrustedRoot $trustedRoot)
    {
    }

    public function assert(FilenameWithChecksum $file, int $bundleIndex, Bundle $bundle): void
    {
        foreach ($bundle->transparencyLogEntries() as $transparencyLogEntry) {
            $inclusionProof = $transparencyLogEntry->inclusionProof();
            if ($inclusionProof === null) {
                continue;
            }

            $checkpointEnvelope = $inclusionProof->checkpointEnvelope();
            if ($checkpointEnvelope === null) {
                continue;
            }

            $parsedCheckpoint = $this->parseCheckpointEnvelope($bundleIndex, $checkpointEnvelope);

            $transparencyLogKey = $this->trustedRoot->resolveTransparencyLogPublicKey($transparencyLogEntry->logId());

            if (! hash_equals(substr($transparencyLogKey['keyId'], 0, 4), $parsedCheckpoint['keyHint'])) {
                throw CheckpointKeyHintMismatch::forIndex($bundleIndex);
            }

            if (
                ! TransparencyLogSignature::verify(
                    $transparencyLogKey,
                    $parsedCheckpoint['noteText'],
                    $parsedCheckpoint['signature'],
                )
            ) {
                throw CheckpointSignatureVerificationFailed::forIndex($bundleIndex);
            }

            if (! hash_equals($inclusionProof->rootHash(), $parsedCheckpoint['rootHash'])) {
                throw CheckpointRootHashMismatch::forIndex($bundleIndex);
            }
        }
    }

    /** @return array{noteText: non-empty-string, keyHint: non-empty-string, signature: non-empty-string, rootHash: non-empty-string} */
    private function parseCheckpointEnvelope(int $bundleIndex, string $envelope): array
    {
        $lines          = explode("\n", $envelope);
        $blankLineIndex = array_search('', $lines, true);

        if (
            $blankLineIndex === false
            || ! isset($lines[$blankLineIndex + 1])
            || $lines[$blankLineIndex + 1] === ''
            || ! isset($lines[2])
            || $lines[2] === ''
        ) {
            throw InvalidCheckpointFormat::forIndex($bundleIndex);
        }

        $noteText = implode("\n", array_slice($lines, 0, $blankLineIndex)) . "\n";

        $signatureLineParts = explode(' ', $lines[$blankLineIndex + 1], 3);
        if (count($signatureLineParts) !== 3) {
            throw InvalidCheckpointFormat::forIndex($bundleIndex);
        }

        $signatureBlob = base64_decode($signatureLineParts[2]);
        if ($signatureBlob === '' || strlen($signatureBlob) <= 4) {
            throw InvalidCheckpointFormat::forIndex($bundleIndex);
        }

        $signature = substr($signatureBlob, 4);
        Assert::stringNotEmpty($signature);

        $rootHash = base64_decode($lines[2]);
        if ($rootHash === '') {
            throw InvalidCheckpointFormat::forIndex($bundleIndex);
        }

        return [
            'noteText' => $noteText,
            'keyHint' => substr($signatureBlob, 0, 4),
            'signature' => $signature,
            'rootHash' => $rootHash,
        ];
    }
}
