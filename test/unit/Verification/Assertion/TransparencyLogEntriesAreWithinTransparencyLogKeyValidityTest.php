<?php

declare(strict_types=1);

namespace ThePhpFoundation\UnitTest\Attestation\Verification\Assertion;

use PHPUnit\Framework\TestCase;
use ThePhpFoundation\Attestation\Bundle;
use ThePhpFoundation\Attestation\FilenameWithChecksum;
use ThePhpFoundation\Attestation\Verification\Assertion\TransparencyLogEntriesAreWithinTransparencyLogKeyValidity;
use ThePhpFoundation\Attestation\Verification\Exception\TransparencyLogKeyOutsideValidityPeriod;
use ThePhpFoundation\Attestation\Verification\TrustedRoot;

use function base64_encode;

/** @covers \ThePhpFoundation\Attestation\Verification\Assertion\TransparencyLogEntriesAreWithinTransparencyLogKeyValidity */
final class TransparencyLogEntriesAreWithinTransparencyLogKeyValidityTest extends TestCase
{
    private const TRUSTED_ROOT_FIXTURE = __DIR__ . '/../../../fixture/trust-root-tlog-validity-end-inclusive-trusted-root.json';
    private const TLOG_KEY_ID          = 'wNI9atQGlz+VWfO6LRygH4QUfY/8W4RFwiT5i5WRgB0=';
    private const TLOG_KEY_VALID_FROM  = 1610452407; // 2021-01-12T11:53:27Z
    private const TLOG_KEY_VALID_TO    = 1689177396; // 2023-07-12T15:56:36Z

    private static function bundleWithIntegratedTime(int $integratedTime): Bundle
    {
        return Bundle::fromBundle([
            'mediaType' => 'application/vnd.dev.sigstore.bundle+json;version=0.3',
            'verificationMaterial' => [
                'certificate' => ['rawBytes' => base64_encode('not a real certificate')],
                'tlogEntries' => [
                    [
                        'logIndex' => '1',
                        'integratedTime' => (string) $integratedTime,
                        'kindVersion' => ['kind' => 'hashedrekord', 'version' => '0.0.1'],
                        'logId' => ['keyId' => self::TLOG_KEY_ID],
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

    private static function check(): TransparencyLogEntriesAreWithinTransparencyLogKeyValidity
    {
        return new TransparencyLogEntriesAreWithinTransparencyLogKeyValidity(new TrustedRoot(self::TRUSTED_ROOT_FIXTURE));
    }

    public function testAcceptsAnIntegratedTimeExactlyAtTheKeysValidityStart(): void
    {
        $this->expectNotToPerformAssertions();
        self::check()->assert(
            FilenameWithChecksum::fromFilenameAndChecksum('irrelevant', 'irrelevant'),
            0,
            self::bundleWithIntegratedTime(self::TLOG_KEY_VALID_FROM),
        );
    }

    public function testAcceptsAnIntegratedTimeExactlyAtTheKeysValidityEnd(): void
    {
        $this->expectNotToPerformAssertions();
        self::check()->assert(
            FilenameWithChecksum::fromFilenameAndChecksum('irrelevant', 'irrelevant'),
            0,
            self::bundleWithIntegratedTime(self::TLOG_KEY_VALID_TO),
        );
    }

    public function testRejectsAnIntegratedTimeBeforeTheKeysValidity(): void
    {
        $this->expectException(TransparencyLogKeyOutsideValidityPeriod::class);
        self::check()->assert(
            FilenameWithChecksum::fromFilenameAndChecksum('irrelevant', 'irrelevant'),
            0,
            self::bundleWithIntegratedTime(self::TLOG_KEY_VALID_FROM - 1),
        );
    }

    public function testRejectsAnIntegratedTimeAfterTheKeysValidity(): void
    {
        $this->expectException(TransparencyLogKeyOutsideValidityPeriod::class);
        self::check()->assert(
            FilenameWithChecksum::fromFilenameAndChecksum('irrelevant', 'irrelevant'),
            0,
            self::bundleWithIntegratedTime(self::TLOG_KEY_VALID_TO + 1),
        );
    }
}
