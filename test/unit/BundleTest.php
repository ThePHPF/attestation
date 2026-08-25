<?php

declare(strict_types=1);

namespace ThePhpFoundation\UnitTest\Attestation;

use PHPUnit\Framework\TestCase;
use ThePhpFoundation\Attestation\Bundle;
use ThePhpFoundation\Attestation\PemCertificate;
use Webmozart\Assert\Assert;

use function file_get_contents;
use function json_decode;

/** @covers \ThePhpFoundation\Attestation\Bundle */
final class BundleTest extends TestCase
{
    private const BUNDLE_FIXTURE                   = __DIR__ . '/../fixture/bundle.json';
    private const CERTIFICATE_CHAIN_BUNDLE_FIXTURE = __DIR__ . '/../fixture/certificate-chain-bundle.json';

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

    public function testFromBundleWithACertificateChainUsesTheLeafCertificate(): void
    {
        $contents = file_get_contents(self::CERTIFICATE_CHAIN_BUNDLE_FIXTURE);
        self::assertIsString($contents);

        /** @var array<array-key, mixed> $decoded */
        $decoded = json_decode($contents, true);

        $bundle = Bundle::fromBundleWithDsseEnvelope($decoded);

        Assert::isArray($decoded['verificationMaterial']);
        Assert::isArray($decoded['verificationMaterial']['x509CertificateChain']);
        $chainCertificates = $decoded['verificationMaterial']['x509CertificateChain']['certificates'];
        Assert::isArray($chainCertificates);

        Assert::isArray($chainCertificates[0]);
        Assert::stringNotEmpty($chainCertificates[0]['rawBytes']);
        Assert::isArray($chainCertificates[1]);
        Assert::stringNotEmpty($chainCertificates[1]['rawBytes']);

        $expectedLeaf      = PemCertificate::fromBase64EncodedDerBytes($chainCertificates[0]['rawBytes']);
        $unexpectedNonLeaf = PemCertificate::fromBase64EncodedDerBytes($chainCertificates[1]['rawBytes']);

        self::assertSame($expectedLeaf->decoratedCertificate(), $bundle->certificate->decoratedCertificate());
        self::assertNotSame($unexpectedNonLeaf->decoratedCertificate(), $bundle->certificate->decoratedCertificate());
    }
}
