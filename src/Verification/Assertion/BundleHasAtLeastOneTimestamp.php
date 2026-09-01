<?php

declare(strict_types=1);

namespace ThePhpFoundation\Attestation\Verification\Assertion;

use ThePhpFoundation\Attestation\Bundle;
use ThePhpFoundation\Attestation\FilenameWithChecksum;
use ThePhpFoundation\Attestation\Verification\Exception\MissingTimestampEvidence;

final class BundleHasAtLeastOneTimestamp implements VerifyBundleCheck
{
    public function assert(FilenameWithChecksum $file, int $bundleIndex, Bundle $bundle): void
    {
        foreach ($bundle->transparencyLogEntries() as $transparencyLogEntry) {
            if ($transparencyLogEntry->integratedTime() !== null) {
                return;
            }
        }

        if ($bundle->rfc3161Timestamps() !== []) {
            return;
        }

        throw MissingTimestampEvidence::forIndex($bundleIndex);
    }
}
