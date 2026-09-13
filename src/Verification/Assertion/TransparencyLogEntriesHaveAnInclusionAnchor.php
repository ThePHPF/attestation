<?php

declare(strict_types=1);

namespace ThePhpFoundation\Attestation\Verification\Assertion;

use ThePhpFoundation\Attestation\Bundle;
use ThePhpFoundation\Attestation\FilenameWithChecksum;
use ThePhpFoundation\Attestation\Verification\Exception\MissingTransparencyLogInclusionAnchor;

/**
 * @internal This is not a public API, so should not be depended upon unless you accept the risk of BC breaks
 *
 * Each entry needs at least one of a verified signed entry timestamp or checkpoint; the checks for those
 * two skip entries missing their own evidence, so this check catches entries missing both.
 */
final class TransparencyLogEntriesHaveAnInclusionAnchor implements VerifyBundleCheck
{
    public function assert(FilenameWithChecksum $file, int $bundleIndex, Bundle $bundle): void
    {
        foreach ($bundle->transparencyLogEntries() as $transparencyLogEntry) {
            $hasSignedEntryTimestamp = $transparencyLogEntry->signedEntryTimestamp() !== null
                && $transparencyLogEntry->integratedTime() !== null;

            $hasCheckpoint = $transparencyLogEntry->inclusionProof()?->checkpointEnvelope() !== null;

            if (! $hasSignedEntryTimestamp && ! $hasCheckpoint) {
                throw MissingTransparencyLogInclusionAnchor::forIndex($bundleIndex);
            }
        }
    }
}
