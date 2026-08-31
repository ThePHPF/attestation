<?php

declare(strict_types=1);

namespace ThePhpFoundation\Attestation\Verification\Assertion;

use ThePhpFoundation\Attestation\Bundle;
use ThePhpFoundation\Attestation\FilenameWithChecksum;
use ThePhpFoundation\Attestation\Verification\Exception\TransparencyLogKeyOutsideValidityPeriod;
use ThePhpFoundation\Attestation\Verification\TrustedRoot;

final class TransparencyLogEntriesAreWithinTransparencyLogKeyValidity implements VerifyBundleCheck
{
    private TrustedRoot $trustedRoot;

    public function __construct(TrustedRoot $trustedRoot)
    {
        $this->trustedRoot = $trustedRoot;
    }

    public function assert(FilenameWithChecksum $file, int $bundleIndex, Bundle $bundle): void
    {
        foreach ($bundle->transparencyLogEntries() as $transparencyLogEntry) {
            $integratedTime = $transparencyLogEntry->integratedTime();
            if ($integratedTime === null) {
                continue;
            }

            $validFor = $this->trustedRoot->resolveTransparencyLogPublicKey($transparencyLogEntry->logId())['validFor'];

            if (
                $integratedTime < $validFor['start']
                || ($validFor['end'] !== null && $integratedTime > $validFor['end'])
            ) {
                throw TransparencyLogKeyOutsideValidityPeriod::forIndex(
                    $bundleIndex,
                    $integratedTime,
                    $validFor['start'],
                    $validFor['end'],
                );
            }
        }
    }
}
