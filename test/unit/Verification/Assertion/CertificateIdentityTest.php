<?php

declare(strict_types=1);

namespace ThePhpFoundation\UnitTest\Attestation\Verification\Assertion;

use PHPUnit\Framework\TestCase;
use ThePhpFoundation\Attestation\Bundle;
use ThePhpFoundation\Attestation\FilenameWithChecksum;
use ThePhpFoundation\Attestation\Verification\Assertion\CertificateIdentity;
use ThePhpFoundation\Attestation\Verification\Exception\CertificateIdentityMismatch;
use Webmozart\Assert\Assert;

use function file_get_contents;
use function json_decode;

/** @covers \ThePhpFoundation\Attestation\Verification\Assertion\CertificateIdentity */
final class CertificateIdentityTest extends TestCase
{
    private const BUNDLE_FIXTURE       = __DIR__ . '/../../../fixture/bundle.json';
    private const CERTIFICATE_IDENTITY = 'https://github.com/php/pie/.github/workflows/build-phar.yml@refs/tags/1.2.0';

    private static function bundle(): Bundle
    {
        $contents = file_get_contents(self::BUNDLE_FIXTURE);
        Assert::stringNotEmpty($contents);

        /** @var array<array-key, mixed> $decoded */
        $decoded = json_decode($contents, true);

        return Bundle::fromBundle($decoded);
    }

    public function testAcceptsAMatchingCertificateIdentity(): void
    {
        $check = new CertificateIdentity(self::CERTIFICATE_IDENTITY);

        $this->expectNotToPerformAssertions();
        $check->assert(FilenameWithChecksum::fromFilenameAndChecksum('irrelevant', 'irrelevant'), 0, self::bundle());
    }

    public function testRejectsAMismatchingCertificateIdentity(): void
    {
        $check = new CertificateIdentity('https://github.com/some-other-org/some-other-repo/.github/workflows/build.yml@refs/heads/main');

        $this->expectException(CertificateIdentityMismatch::class);
        $check->assert(FilenameWithChecksum::fromFilenameAndChecksum('irrelevant', 'irrelevant'), 0, self::bundle());
    }
}
