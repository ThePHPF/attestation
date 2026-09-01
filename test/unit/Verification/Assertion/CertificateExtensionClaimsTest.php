<?php

declare(strict_types=1);

namespace ThePhpFoundation\UnitTest\Attestation\Verification\Assertion;

use PHPUnit\Framework\TestCase;
use ThePhpFoundation\Attestation\Bundle;
use ThePhpFoundation\Attestation\FilenameWithChecksum;
use ThePhpFoundation\Attestation\FulcioSigstoreOidExtensions;
use ThePhpFoundation\Attestation\Verification\Assertion\CertificateExtensionClaims;
use ThePhpFoundation\Attestation\Verification\Exception\MismatchingExtensionValues;
use Webmozart\Assert\Assert;

use function file_get_contents;
use function json_decode;

/** @covers \ThePhpFoundation\Attestation\Verification\Assertion\CertificateExtensionClaims */
final class CertificateExtensionClaimsTest extends TestCase
{
    private const BUNDLE_FIXTURE = __DIR__ . '/../../../fixture/bundle.json';

    private static function bundle(): Bundle
    {
        $contents = file_get_contents(self::BUNDLE_FIXTURE);
        Assert::stringNotEmpty($contents);

        /** @var array<array-key, mixed> $decoded */
        $decoded = json_decode($contents, true);

        return Bundle::fromBundle($decoded);
    }

    public function testAcceptsMatchingExtensionClaims(): void
    {
        $check = new CertificateExtensionClaims([
            FulcioSigstoreOidExtensions::ISSUER_V2 => 'https://token.actions.githubusercontent.com',
            FulcioSigstoreOidExtensions::SOURCE_REPOSITORY_URI => 'https://github.com/php/pie',
            FulcioSigstoreOidExtensions::SOURCE_REPOSITORY_OWNER_URI => 'https://github.com/php',
        ]);

        $this->expectNotToPerformAssertions();
        $check->assert(FilenameWithChecksum::fromFilenameAndChecksum('irrelevant', 'irrelevant'), 0, self::bundle());
    }

    public function testRejectsAMismatchingExtensionClaim(): void
    {
        $check = new CertificateExtensionClaims([
            FulcioSigstoreOidExtensions::ISSUER_V2 => 'https://token.actions.githubusercontent.com',
            FulcioSigstoreOidExtensions::SOURCE_REPOSITORY_URI => 'https://github.com/php/pie',
            FulcioSigstoreOidExtensions::SOURCE_REPOSITORY_OWNER_URI => 'https://github.com/asgrim',
        ]);

        $this->expectException(MismatchingExtensionValues::class);
        $check->assert(FilenameWithChecksum::fromFilenameAndChecksum('irrelevant', 'irrelevant'), 0, self::bundle());
    }
}
