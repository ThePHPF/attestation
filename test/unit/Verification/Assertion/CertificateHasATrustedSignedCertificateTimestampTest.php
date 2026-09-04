<?php

declare(strict_types=1);

namespace ThePhpFoundation\UnitTest\Attestation\Verification\Assertion;

use PHPUnit\Framework\TestCase;
use ThePhpFoundation\Attestation\Bundle;
use ThePhpFoundation\Attestation\FilenameWithChecksum;
use ThePhpFoundation\Attestation\Verification\Assertion\CertificateHasATrustedSignedCertificateTimestamp;
use ThePhpFoundation\Attestation\Verification\Exception\UntrustedCertificateTransparencyLogKey;
use ThePhpFoundation\Attestation\Verification\TrustedRoot;
use Webmozart\Assert\Assert;

use function file_get_contents;
use function json_decode;

/** @covers \ThePhpFoundation\Attestation\Verification\Assertion\CertificateHasATrustedSignedCertificateTimestamp */
final class CertificateHasATrustedSignedCertificateTimestampTest extends TestCase
{
    private const PRODUCTION_TRUSTED_ROOT = __DIR__ . '/../../../../resources/trusted-root.jsonl';
    private const BUNDLE_FIXTURE          = __DIR__ . '/../../../fixture/bundle.json';

    private const INVALID_CT_KEY_FIXTURE      = __DIR__ . '/../../../fixture/invalid-ct-key-fail.json';
    private const INVALID_CT_KEY_TRUSTED_ROOT = __DIR__ . '/../../../fixture/invalid-ct-key-fail-trusted-root.json';

    private static function loadFixtureBundle(string $path): Bundle
    {
        $contents = file_get_contents($path);
        Assert::stringNotEmpty($contents);

        /** @var array<array-key, mixed> $decoded */
        $decoded = json_decode($contents, true);

        return Bundle::fromBundle($decoded);
    }

    public function testAcceptsACertificateWithATrustedSignedCertificateTimestamp(): void
    {
        $check = new CertificateHasATrustedSignedCertificateTimestamp(new TrustedRoot(self::PRODUCTION_TRUSTED_ROOT));

        $this->expectNotToPerformAssertions();
        $check->assert(
            FilenameWithChecksum::fromFilenameAndChecksum('irrelevant', 'irrelevant'),
            0,
            self::loadFixtureBundle(self::BUNDLE_FIXTURE),
        );
    }

    public function testRejectsACertificateWhoseSignedCertificateTimestampReferencesAnUntrustedCtLog(): void
    {
        $check = new CertificateHasATrustedSignedCertificateTimestamp(new TrustedRoot(self::INVALID_CT_KEY_TRUSTED_ROOT));

        $this->expectException(UntrustedCertificateTransparencyLogKey::class);
        $check->assert(
            FilenameWithChecksum::fromFilenameAndChecksum('irrelevant', 'irrelevant'),
            0,
            self::loadFixtureBundle(self::INVALID_CT_KEY_FIXTURE),
        );
    }
}
