<?php

declare(strict_types=1);

namespace ThePhpFoundation\UnitTest\Attestation\Verification\Assertion;

use PHPUnit\Framework\TestCase;
use ThePhpFoundation\Attestation\Bundle;
use ThePhpFoundation\Attestation\FilenameWithChecksum;
use ThePhpFoundation\Attestation\Verification\Assertion\CertificateOidcIssuer;
use ThePhpFoundation\Attestation\Verification\Exception\MismatchingExtensionValues;
use Webmozart\Assert\Assert;

use function file_get_contents;
use function json_decode;

/** @covers \ThePhpFoundation\Attestation\Verification\Assertion\CertificateOidcIssuer */
final class CertificateOidcIssuerTest extends TestCase
{
    private const BUNDLE_FIXTURE            = __DIR__ . '/../../../fixture/bundle.json';
    private const HISTORICAL_BUNDLE_FIXTURE = __DIR__ . '/../../../fixture/python-3.9.14-historical.json';

    private static function bundle(string $path): Bundle
    {
        $contents = file_get_contents($path);
        Assert::stringNotEmpty($contents);

        /** @var array<array-key, mixed> $decoded */
        $decoded = json_decode($contents, true);

        return Bundle::fromBundle($decoded);
    }

    public function testAcceptsAMatchingOidcIssuer(): void
    {
        $check = new CertificateOidcIssuer('https://token.actions.githubusercontent.com');

        $this->expectNotToPerformAssertions();
        $check->assert(FilenameWithChecksum::fromFilenameAndChecksum('irrelevant', 'irrelevant'), 0, self::bundle(self::BUNDLE_FIXTURE));
    }

    public function testRejectsAMismatchingOidcIssuer(): void
    {
        $check = new CertificateOidcIssuer('https://an-untrusted-issuer.example.com');

        $this->expectException(MismatchingExtensionValues::class);
        $check->assert(FilenameWithChecksum::fromFilenameAndChecksum('irrelevant', 'irrelevant'), 0, self::bundle(self::BUNDLE_FIXTURE));
    }

    public function testAcceptsACertificateThatOnlyHasTheLegacyV1IssuerExtension(): void
    {
        $check = new CertificateOidcIssuer('https://github.com/login/oauth');

        $this->expectNotToPerformAssertions();
        $check->assert(FilenameWithChecksum::fromFilenameAndChecksum('irrelevant', 'irrelevant'), 0, self::bundle(self::HISTORICAL_BUNDLE_FIXTURE));
    }
}
