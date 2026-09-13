<?php

declare(strict_types=1);

namespace ThePhpFoundation\UnitTest\Attestation\Verification\Assertion;

use PHPUnit\Framework\TestCase;
use ThePhpFoundation\Attestation\Bundle;
use ThePhpFoundation\Attestation\FilenameWithChecksum;
use ThePhpFoundation\Attestation\Verification\Assertion\BundleMediaTypeIsSupported;
use ThePhpFoundation\Attestation\Verification\Exception\UnsupportedBundleMediaType;

use function base64_encode;

/** @covers \ThePhpFoundation\Attestation\Verification\Assertion\BundleMediaTypeIsSupported */
final class BundleMediaTypeIsSupportedTest extends TestCase
{
    private static function bundleWithMediaType(string $mediaType): Bundle
    {
        return Bundle::fromBundle([
            'mediaType' => $mediaType,
            'verificationMaterial' => [
                'certificate' => ['rawBytes' => base64_encode('not a real certificate')],
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

    /** @return list<array{0: non-empty-string}> */
    public static function supportedMediaTypeProvider(): array
    {
        return [
            ['application/vnd.dev.sigstore.bundle+json;version=0.1'],
            ['application/vnd.dev.sigstore.bundle+json;version=0.2'],
            ['application/vnd.dev.sigstore.bundle+json;version=0.3'],
            ['application/vnd.dev.sigstore.bundle.v0.3+json'],
        ];
    }

    /** @dataProvider supportedMediaTypeProvider */
    public function testAcceptsEachSupportedMediaType(string $mediaType): void
    {
        $this->expectNotToPerformAssertions();
        (new BundleMediaTypeIsSupported())->assert(
            FilenameWithChecksum::fromFilenameAndChecksum('irrelevant', 'irrelevant'),
            0,
            self::bundleWithMediaType($mediaType),
        );
    }

    public function testRejectsAnUnsupportedMediaType(): void
    {
        $this->expectException(UnsupportedBundleMediaType::class);
        (new BundleMediaTypeIsSupported())->assert(
            FilenameWithChecksum::fromFilenameAndChecksum('irrelevant', 'irrelevant'),
            0,
            self::bundleWithMediaType('application/vnd.dev.sigstore.bundle+json;version=99.9'),
        );
    }
}
