<?php

declare(strict_types=1);

namespace ThePhpFoundation\Attestation\Verification\Assertion;

use ThePhpFoundation\Attestation\Bundle;
use ThePhpFoundation\Attestation\FilenameWithChecksum;
use ThePhpFoundation\Attestation\Verification\Exception\InvalidIntegratedTime;
use Webmozart\Assert\Assert;

use function openssl_x509_parse;

/** @internal This is not a public API, so should not be depended upon unless you accept the risk of BC breaks */
final class TransparencyLogEntriesAreWithinCertificateValidity implements VerifyBundleCheck
{
    public function assert(FilenameWithChecksum $file, int $bundleIndex, Bundle $bundle): void
    {
        if ($bundle->transparencyLogEntries() === []) {
            return;
        }

        $certificateInfo = openssl_x509_parse($bundle->certificate()->decoratedCertificate());
        Assert::isArray($certificateInfo);
        Assert::keyExists($certificateInfo, 'validFrom_time_t');
        Assert::integer($certificateInfo['validFrom_time_t']);
        Assert::keyExists($certificateInfo, 'validTo_time_t');
        Assert::integer($certificateInfo['validTo_time_t']);

        $certificateValidFrom = $certificateInfo['validFrom_time_t'];
        $certificateValidTo   = $certificateInfo['validTo_time_t'];

        foreach ($bundle->transparencyLogEntries() as $transparencyLogEntry) {
            if ($transparencyLogEntry->integratedTime() === null) {
                continue;
            }

            if (
                $transparencyLogEntry->integratedTime() < $certificateValidFrom
                || $transparencyLogEntry->integratedTime() > $certificateValidTo
            ) {
                throw InvalidIntegratedTime::forIndex(
                    $bundleIndex,
                    $transparencyLogEntry->integratedTime(),
                    $certificateValidFrom,
                    $certificateValidTo,
                );
            }
        }
    }
}
