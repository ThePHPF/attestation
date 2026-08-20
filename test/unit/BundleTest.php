<?php

declare(strict_types=1);

namespace ThePhpFoundation\UnitTest\Attestation;

use PHPUnit\Framework\TestCase;
use ThePhpFoundation\Attestation\Bundle;

use function file_get_contents;
use function json_decode;

/** @covers \ThePhpFoundation\Attestation\Bundle */
final class BundleTest extends TestCase
{
    private const BUNDLE_FIXTURE = __DIR__ . '/../fixture/bundle.json';

    public function testFromBundleWithDsseEnvelope(): void
    {
        $contents = file_get_contents(self::BUNDLE_FIXTURE);
        self::assertIsString($contents);

        /** @var array<array-key, mixed> $decoded */
        $decoded = json_decode($contents, true);

        $bundle = Bundle::fromBundleWithDsseEnvelope($decoded);

        self::assertNotSame('', $bundle->certificate->decoratedCertificate());
        self::assertNotSame('', $bundle->dsseEnvelope->payload);
    }
}
