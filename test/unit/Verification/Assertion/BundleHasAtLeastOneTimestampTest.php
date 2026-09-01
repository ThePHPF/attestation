<?php

declare(strict_types=1);

namespace ThePhpFoundation\UnitTest\Attestation\Verification\Assertion;

use PHPUnit\Framework\TestCase;
use ThePhpFoundation\Attestation\Bundle;
use ThePhpFoundation\Attestation\FilenameWithChecksum;
use ThePhpFoundation\Attestation\Verification\Assertion\BundleHasAtLeastOneTimestamp;
use ThePhpFoundation\Attestation\Verification\Exception\MissingTimestampEvidence;

use function array_merge;
use function base64_encode;

/** @covers \ThePhpFoundation\Attestation\Verification\Assertion\BundleHasAtLeastOneTimestamp */
final class BundleHasAtLeastOneTimestampTest extends TestCase
{
    /** @param array<array-key, mixed> $verificationMaterialOverrides */
    private static function bundle(array $verificationMaterialOverrides): Bundle
    {
        return Bundle::fromBundle([
            'mediaType' => 'application/vnd.dev.sigstore.bundle+json;version=0.3',
            'verificationMaterial' => array_merge(
                ['certificate' => ['rawBytes' => base64_encode('not a real certificate')]],
                $verificationMaterialOverrides,
            ),
            'messageSignature' => [
                'messageDigest' => [
                    'algorithm' => 'SHA2_256',
                    'digest' => base64_encode('not a real digest'),
                ],
                'signature' => base64_encode('not a real signature'),
            ],
        ]);
    }

    /** @return array<array-key, mixed> */
    private static function tlogEntryWithIntegratedTime(string|null $integratedTime): array
    {
        $entry = [
            'logIndex' => '0',
            'kindVersion' => ['kind' => 'hashedrekord', 'version' => '0.0.1'],
            'logId' => ['keyId' => base64_encode('not a real log id')],
            'canonicalizedBody' => base64_encode('not a real body'),
        ];

        if ($integratedTime !== null) {
            $entry['integratedTime'] = $integratedTime;
        }

        return $entry;
    }

    public function testAcceptsABundleWithATransparencyLogEntryIntegratedTime(): void
    {
        $this->expectNotToPerformAssertions();
        (new BundleHasAtLeastOneTimestamp())->assert(
            FilenameWithChecksum::fromFilenameAndChecksum('irrelevant', 'irrelevant'),
            0,
            self::bundle(['tlogEntries' => [self::tlogEntryWithIntegratedTime('12345')]]),
        );
    }

    public function testAcceptsABundleWithAnRfc3161TimestampAndNoIntegratedTime(): void
    {
        $this->expectNotToPerformAssertions();
        (new BundleHasAtLeastOneTimestamp())->assert(
            FilenameWithChecksum::fromFilenameAndChecksum('irrelevant', 'irrelevant'),
            0,
            self::bundle([
                'tlogEntries' => [self::tlogEntryWithIntegratedTime(null)],
                'timestampVerificationData' => [
                    'rfc3161Timestamps' => [
                        ['signedTimestamp' => base64_encode('not a real timestamp token')],
                    ],
                ],
            ]),
        );
    }

    public function testRejectsABundleWithNeitherAnIntegratedTimeNorAnRfc3161Timestamp(): void
    {
        $this->expectException(MissingTimestampEvidence::class);
        (new BundleHasAtLeastOneTimestamp())->assert(
            FilenameWithChecksum::fromFilenameAndChecksum('irrelevant', 'irrelevant'),
            0,
            self::bundle(['tlogEntries' => [self::tlogEntryWithIntegratedTime(null)]]),
        );
    }
}
