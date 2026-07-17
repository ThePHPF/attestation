<?php

declare(strict_types=1);

namespace ThePhpFoundation\UnitTest\Attestation\FlowSnappy;

use PHPUnit\Framework\TestCase;
use ThePhpFoundation\Attestation\FlowSnappy\Snappy;

use function file_get_contents;

/** @covers \ThePhpFoundation\Attestation\FlowSnappy\Snappy */
final class SnappyTest extends TestCase
{
    private const COMPRESSED_BUNDLE_FIXTURE   = __DIR__ . '/../../fixture/bundle.json.sn';
    private const DECOMPRESSED_BUNDLE_FIXTURE = __DIR__ . '/../../fixture/bundle.json';

    public function testUncompressesRealAttestationBundleFixture(): void
    {
        $compressed   = (string) file_get_contents(self::COMPRESSED_BUNDLE_FIXTURE);
        $expectedJson = (string) file_get_contents(self::DECOMPRESSED_BUNDLE_FIXTURE);

        $actual = (new Snappy())->uncompress($compressed);

        self::assertSame($expectedJson, $actual);
    }
}
