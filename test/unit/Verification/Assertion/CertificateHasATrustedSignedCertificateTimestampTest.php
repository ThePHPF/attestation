<?php

declare(strict_types=1);

namespace ThePhpFoundation\UnitTest\Attestation\Verification\Assertion;

use PHPUnit\Framework\TestCase;
use ReflectionMethod;
use ThePhpFoundation\Attestation\Bundle;
use ThePhpFoundation\Attestation\FilenameWithChecksum;
use ThePhpFoundation\Attestation\Verification\Assertion\CertificateHasATrustedSignedCertificateTimestamp;
use ThePhpFoundation\Attestation\Verification\Exception\SignedCertificateTimestampVerificationFailed;
use ThePhpFoundation\Attestation\Verification\Exception\UntrustedCertificateTransparencyLogKey;
use ThePhpFoundation\Attestation\Verification\TrustedRoot;
use Webmozart\Assert\Assert;

use function base64_decode;
use function base64_encode;
use function chr;
use function file_get_contents;
use function json_decode;
use function ord;
use function strlen;
use function strpos;
use function substr_replace;

use const PHP_VERSION_ID;

/** @covers \ThePhpFoundation\Attestation\Verification\Assertion\CertificateHasATrustedSignedCertificateTimestamp */
final class CertificateHasATrustedSignedCertificateTimestampTest extends TestCase
{
    private const PRODUCTION_TRUSTED_ROOT = __DIR__ . '/../../../../resources/trusted-root.jsonl';
    private const BUNDLE_FIXTURE          = __DIR__ . '/../../../fixture/bundle.json';

    private const INVALID_CT_KEY_FIXTURE      = __DIR__ . '/../../../fixture/invalid-ct-key-fail.json';
    private const INVALID_CT_KEY_TRUSTED_ROOT = __DIR__ . '/../../../fixture/invalid-ct-key-fail-trusted-root.json';

    private const SCT_WITH_EXTENSIONS_BUNDLE_FIXTURE       = __DIR__ . '/../../../fixture/bundle-with-sct-with-extensions.json';
    private const SCT_WITH_EXTENSIONS_TRUSTED_ROOT_FIXTURE = __DIR__ . '/../../../fixture/bundle-with-sct-with-extensions-trusted-root.json';

    private static function loadFixtureBundle(string $path): Bundle
    {
        return Bundle::fromBundle(self::decodeFixture($path));
    }

    /** @return array<array-key, mixed> */
    private static function decodeFixture(string $path): array
    {
        $contents = file_get_contents($path);
        Assert::stringNotEmpty($contents);

        /** @var array<array-key, mixed> $decoded */
        $decoded = json_decode($contents, true);

        return $decoded;
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

    public function testAcceptsARealCertificateWithASignedCertificateTimestampCarryingExtensions(): void
    {
        $check = new CertificateHasATrustedSignedCertificateTimestamp(new TrustedRoot(self::SCT_WITH_EXTENSIONS_TRUSTED_ROOT_FIXTURE));

        $this->expectNotToPerformAssertions();
        $check->assert(
            FilenameWithChecksum::fromFilenameAndChecksum('irrelevant', 'irrelevant'),
            0,
            self::loadFixtureBundle(self::SCT_WITH_EXTENSIONS_BUNDLE_FIXTURE),
        );
    }

    public function testRejectsACertificateWithATamperedSignedCertificateTimestampSignature(): void
    {
        $decoded = self::decodeFixture(self::SCT_WITH_EXTENSIONS_BUNDLE_FIXTURE);
        Assert::isArray($decoded['verificationMaterial']);
        Assert::isArray($decoded['verificationMaterial']['certificate']);
        Assert::stringNotEmpty($decoded['verificationMaterial']['certificate']['rawBytes']);

        $certificateDer = base64_decode($decoded['verificationMaterial']['certificate']['rawBytes']);
        Assert::stringNotEmpty($certificateDer);

        $trustedRoot = new TrustedRoot(self::SCT_WITH_EXTENSIONS_TRUSTED_ROOT_FIXTURE);
        $check       = new CertificateHasATrustedSignedCertificateTimestamp($trustedRoot);

        $extractSignedCertificateTimestamps = new ReflectionMethod($check, 'extractSignedCertificateTimestamps');
        if (PHP_VERSION_ID < 80100) {
            $extractSignedCertificateTimestamps->setAccessible(true);
        }

        $signedCertificateTimestamps = $extractSignedCertificateTimestamps->invoke($check, $certificateDer);
        Assert::isArray($signedCertificateTimestamps);
        Assert::isArray($signedCertificateTimestamps[0]);
        Assert::stringNotEmpty($signedCertificateTimestamps[0]['signature']);
        $signature = $signedCertificateTimestamps[0]['signature'];

        $signatureOffset = strpos($certificateDer, $signature);
        Assert::notFalse($signatureOffset);

        $lastByteOffset  = $signatureOffset + strlen($signature) - 1;
        $tamperedByte    = chr(ord($certificateDer[$lastByteOffset]) ^ 0xFF);
        $tamperedCertDer = substr_replace($certificateDer, $tamperedByte, $lastByteOffset, 1);

        $decoded['verificationMaterial']['certificate']['rawBytes'] = base64_encode($tamperedCertDer);

        $this->expectException(SignedCertificateTimestampVerificationFailed::class);
        $check->assert(
            FilenameWithChecksum::fromFilenameAndChecksum('irrelevant', 'irrelevant'),
            0,
            Bundle::fromBundle($decoded),
        );
    }
}
