<?php

declare(strict_types=1);

namespace ThePhpFoundation\UnitTest\Attestation\Verification\Assertion;

use PHPUnit\Framework\TestCase;
use ThePhpFoundation\Attestation\Bundle;
use ThePhpFoundation\Attestation\FilenameWithChecksum;
use ThePhpFoundation\Attestation\Verification\Assertion\TransparencyLogEntriesAreWithinCertificateValidity;
use ThePhpFoundation\Attestation\Verification\Exception\InvalidIntegratedTime;
use Webmozart\Assert\Assert;

use function base64_encode;
use function file_get_contents;
use function json_decode;
use function openssl_x509_parse;

/** @covers \ThePhpFoundation\Attestation\Verification\Assertion\TransparencyLogEntriesAreWithinCertificateValidity */
final class TransparencyLogEntriesAreWithinCertificateValidityTest extends TestCase
{
    private const CERTIFICATE_FIXTURE = __DIR__ . '/../../../fixture/integrated-time-in-future-fail.json';

    /** @return non-empty-string */
    private static function certificateRawBytes(): string
    {
        $contents = file_get_contents(self::CERTIFICATE_FIXTURE);
        Assert::stringNotEmpty($contents);

        /** @var array<array-key, mixed> $decoded */
        $decoded = json_decode($contents, true);
        Assert::isArray($decoded['verificationMaterial']);
        Assert::isArray($decoded['verificationMaterial']['certificate']);
        Assert::stringNotEmpty($decoded['verificationMaterial']['certificate']['rawBytes']);

        return $decoded['verificationMaterial']['certificate']['rawBytes'];
    }

    private static function bundleWithIntegratedTime(int $integratedTime): Bundle
    {
        return Bundle::fromBundle([
            'mediaType' => 'application/vnd.dev.sigstore.bundle+json;version=0.3',
            'verificationMaterial' => [
                'certificate' => ['rawBytes' => self::certificateRawBytes()],
                'tlogEntries' => [
                    [
                        'logIndex' => '1',
                        'integratedTime' => (string) $integratedTime,
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

    /** @return array{validFrom: int, validTo: int} */
    private static function certificateValidity(): array
    {
        $certificateInfo = openssl_x509_parse("-----BEGIN CERTIFICATE-----\n" . self::certificateRawBytes() . "\n-----END CERTIFICATE-----\n");
        Assert::isArray($certificateInfo);
        Assert::integer($certificateInfo['validFrom_time_t']);
        Assert::integer($certificateInfo['validTo_time_t']);

        return ['validFrom' => $certificateInfo['validFrom_time_t'], 'validTo' => $certificateInfo['validTo_time_t']];
    }

    public function testAcceptsAnIntegratedTimeWithinTheCertificatesValidity(): void
    {
        $this->expectNotToPerformAssertions();
        (new TransparencyLogEntriesAreWithinCertificateValidity())->assert(
            FilenameWithChecksum::fromFilenameAndChecksum('irrelevant', 'irrelevant'),
            0,
            self::bundleWithIntegratedTime(self::certificateValidity()['validFrom']),
        );
    }

    public function testRejectsAnIntegratedTimeBeforeTheCertificatesValidity(): void
    {
        $this->expectException(InvalidIntegratedTime::class);
        (new TransparencyLogEntriesAreWithinCertificateValidity())->assert(
            FilenameWithChecksum::fromFilenameAndChecksum('irrelevant', 'irrelevant'),
            0,
            self::bundleWithIntegratedTime(self::certificateValidity()['validFrom'] - 1),
        );
    }

    public function testRejectsAnIntegratedTimeAfterTheCertificatesValidity(): void
    {
        $this->expectException(InvalidIntegratedTime::class);
        (new TransparencyLogEntriesAreWithinCertificateValidity())->assert(
            FilenameWithChecksum::fromFilenameAndChecksum('irrelevant', 'irrelevant'),
            0,
            self::bundleWithIntegratedTime(self::certificateValidity()['validTo'] + 1),
        );
    }
}
