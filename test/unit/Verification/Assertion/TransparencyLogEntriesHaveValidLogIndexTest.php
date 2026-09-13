<?php

declare(strict_types=1);

namespace ThePhpFoundation\UnitTest\Attestation\Verification\Assertion;

use PHPUnit\Framework\TestCase;
use ThePhpFoundation\Attestation\Bundle;
use ThePhpFoundation\Attestation\FilenameWithChecksum;
use ThePhpFoundation\Attestation\Verification\Assertion\TransparencyLogEntriesHaveValidLogIndex;
use ThePhpFoundation\Attestation\Verification\Exception\InvalidLogIndex;

use function base64_encode;

/** @covers \ThePhpFoundation\Attestation\Verification\Assertion\TransparencyLogEntriesHaveValidLogIndex */
final class TransparencyLogEntriesHaveValidLogIndexTest extends TestCase
{
    private static function bundleWithLogIndex(string $logIndex): Bundle
    {
        return Bundle::fromBundle([
            'mediaType' => 'application/vnd.dev.sigstore.bundle+json;version=0.3',
            'verificationMaterial' => [
                'certificate' => ['rawBytes' => base64_encode('not a real certificate')],
                'tlogEntries' => [
                    [
                        'logIndex' => $logIndex,
                        'kindVersion' => ['kind' => 'hashedrekord', 'version' => '0.0.1'],
                        'logId' => ['keyId' => base64_encode('not a real log id')],
                        'canonicalizedBody' => base64_encode('not a real body'),
                    ],
                ],
            ],
            'messageSignature' => [
                'messageDigest' => [
                    'algorithm' => 'SHA2_256',
                    'digest' => base64_encode('not a real digest'),
                ],
                'signature' => base64_encode('not a real signature'),
            ],
        ]);
    }

    public function testAcceptsANonNegativeLogIndex(): void
    {
        $this->expectNotToPerformAssertions();
        (new TransparencyLogEntriesHaveValidLogIndex())->assert(
            FilenameWithChecksum::fromFilenameAndChecksum('irrelevant', 'irrelevant'),
            0,
            self::bundleWithLogIndex('0'),
        );
    }

    public function testRejectsANegativeLogIndex(): void
    {
        $this->expectException(InvalidLogIndex::class);
        (new TransparencyLogEntriesHaveValidLogIndex())->assert(
            FilenameWithChecksum::fromFilenameAndChecksum('irrelevant', 'irrelevant'),
            0,
            self::bundleWithLogIndex('-1'),
        );
    }
}
