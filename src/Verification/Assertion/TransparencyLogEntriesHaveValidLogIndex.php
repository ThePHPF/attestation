<?php

declare(strict_types=1);

namespace ThePhpFoundation\Attestation\Verification\Assertion;

use ThePhpFoundation\Attestation\Bundle;
use ThePhpFoundation\Attestation\FilenameWithChecksum;
use ThePhpFoundation\Attestation\Verification\Exception\InvalidLogIndex;

final class TransparencyLogEntriesHaveValidLogIndex implements VerifyBundleCheck
{
    public function assert(FilenameWithChecksum $file, int $bundleIndex, Bundle $bundle): void
    {
        foreach ($bundle->transparencyLogEntries() as $transparencyLogEntry) {
            if ($transparencyLogEntry->logIndex() < 0) {
                throw InvalidLogIndex::forIndex($bundleIndex, $transparencyLogEntry->logIndex());
            }
        }
    }
}
