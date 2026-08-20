<?php

declare(strict_types=1);

namespace ThePhpFoundation\UnitTest\Attestation\Verification;

use PHPUnit\Framework\TestCase;
use ThePhpFoundation\Attestation\Bundle;
use ThePhpFoundation\Attestation\FilenameWithChecksum;
use ThePhpFoundation\Attestation\FulcioSigstoreOidExtensions;
use ThePhpFoundation\Attestation\Verification\Exception\DigestMismatch;
use ThePhpFoundation\Attestation\Verification\Exception\IssuerCertificateVerificationFailed;
use ThePhpFoundation\Attestation\Verification\Exception\MismatchingExtensionValues;
use ThePhpFoundation\Attestation\Verification\Exception\NoIssuerCertificateInTrustedRoot;
use ThePhpFoundation\Attestation\Verification\Exception\SignatureVerificationFailed;
use ThePhpFoundation\Attestation\Verification\VerifyBundleWithOpenSsl;
use Webmozart\Assert\Assert;

use function file_get_contents;
use function json_decode;

/** @covers \ThePhpFoundation\Attestation\Verification\VerifyBundleWithOpenSsl */
class VerifyBundleWithOpenSslTest extends TestCase
{
    private const BUNDLE_FIXTURE   = __DIR__ . '/../../fixture/bundle.json';
    private const GENUINE_PIE_PHAR = __DIR__ . '/../../fixture/genuine-pie.phar';

    private VerifyBundleWithOpenSsl $verifier;

    public function setUp(): void
    {
        $this->verifier = VerifyBundleWithOpenSsl::factory();
    }

    /** @return non-empty-list<Bundle> */
    private function loadFixtureBundle(): array
    {
        $contents = file_get_contents(self::BUNDLE_FIXTURE);
        Assert::stringNotEmpty($contents);

        /** @var array<array-key, mixed> $decoded */
        $decoded = json_decode($contents, true);

        return [Bundle::fromBundleWithDsseEnvelope($decoded)];
    }

    public function testSuccessfulVerification(): void
    {
        $this->expectNotToPerformAssertions();
        $this->verifier->verify(
            $this->loadFixtureBundle(),
            FilenameWithChecksum::fromFilename(self::GENUINE_PIE_PHAR),
            'pie.phar',
            [
                FulcioSigstoreOidExtensions::ISSUER_V2 => 'https://token.actions.githubusercontent.com',
                FulcioSigstoreOidExtensions::SOURCE_REPOSITORY_URI => 'https://github.com/php/pie',
                FulcioSigstoreOidExtensions::SOURCE_REPOSITORY_OWNER_URI => 'https://github.com/php',
            ],
        );
    }

    public function testMismatchingExtensionClaimsAreRejected(): void
    {
        $this->expectException(MismatchingExtensionValues::class);
        $this->verifier->verify(
            $this->loadFixtureBundle(),
            FilenameWithChecksum::fromFilename(self::GENUINE_PIE_PHAR),
            'pie.phar',
            [
                FulcioSigstoreOidExtensions::ISSUER_V2 => 'https://token.actions.githubusercontent.com',
                FulcioSigstoreOidExtensions::SOURCE_REPOSITORY_URI => 'https://github.com/php/pie',
                FulcioSigstoreOidExtensions::SOURCE_REPOSITORY_OWNER_URI => 'https://github.com/asgrim',
            ],
        );
    }

    public function testCertificateWasNotVerifiedFromTrustedRoot(): void
    {
        $this->expectException(IssuerCertificateVerificationFailed::class);
        self::markTestIncomplete();
    }

    public function testCertificateWasNotFoundInAnyTrustedRoot(): void
    {
        $this->expectException(NoIssuerCertificateInTrustedRoot::class);
        self::markTestIncomplete();
    }

    public function testDsseEnvelopeSignatureVerificationFailed(): void
    {
        $this->expectException(SignatureVerificationFailed::class);
        self::markTestIncomplete();
    }

    public function testDigestMismatchInAttestation(): void
    {
        $this->expectException(DigestMismatch::class);
        self::markTestIncomplete();
    }
}
