<?php

declare(strict_types=1);

namespace ThePhpFoundation\IntegrationTest\Attestation\Verification;

use PHPUnit\Framework\TestCase;
use ThePhpFoundation\Attestation\FilenameWithChecksum;
use ThePhpFoundation\Attestation\FulcioSigstoreOidExtensions;
use ThePhpFoundation\Attestation\Verification\Exception\DigestMismatch;
use ThePhpFoundation\Attestation\Verification\Exception\IssuerCertificateVerificationFailed;
use ThePhpFoundation\Attestation\Verification\Exception\MismatchingExtensionValues;
use ThePhpFoundation\Attestation\Verification\Exception\MissingAttestation;
use ThePhpFoundation\Attestation\Verification\Exception\NoIssuerCertificateInTrustedRoot;
use ThePhpFoundation\Attestation\Verification\Exception\SignatureVerificationFailed;
use ThePhpFoundation\Attestation\Verification\VerifyAttestationWithOpenSsl;

class VerifyAttestationWithOpenSslTest extends TestCase
{
    private const GENUINE_PIE_PHAR                         = __DIR__ . '/../../fixture/genuine-pie.phar';
    private const PIE_WITH_ATTESTATION_FOR_DIFFERENT_OWNER = __DIR__ . '/../../fixture/pie-with-attestation-for-different-owner.phar';

    private VerifyAttestationWithOpenSsl $verifier;

    public function setUp(): void
    {
        $this->verifier = VerifyAttestationWithOpenSsl::factory();
    }

    public function testSuccessfulVerification(): void
    {
        $this->expectNotToPerformAssertions();
        $this->verifier->verify(
            FilenameWithChecksum::fromFilename(self::GENUINE_PIE_PHAR),
            'php',
            'pie.phar',
            [
                FulcioSigstoreOidExtensions::ISSUER_V2 => 'https://token.actions.githubusercontent.com',
                FulcioSigstoreOidExtensions::SOURCE_REPOSITORY_URI => 'https://github.com/php/pie',
                FulcioSigstoreOidExtensions::SOURCE_REPOSITORY_OWNER_URI => 'https://github.com/php',
            ],
        );
    }

    public function testMissingAttestation(): void
    {
        $this->expectException(MissingAttestation::class);
        $this->verifier->verify(
            FilenameWithChecksum::fromFilename(__FILE__),
            'php',
            'pie.phar',
            [
                FulcioSigstoreOidExtensions::ISSUER_V2 => 'https://token.actions.githubusercontent.com',
                FulcioSigstoreOidExtensions::SOURCE_REPOSITORY_URI => 'https://github.com/php/pie',
                FulcioSigstoreOidExtensions::SOURCE_REPOSITORY_OWNER_URI => 'https://github.com/php',
            ],
        );
    }

    public function testArtifactWithAttestationFromDifferentOwner(): void
    {
        $this->expectException(MismatchingExtensionValues::class);
        $this->verifier->verify(
            FilenameWithChecksum::fromFilename(self::PIE_WITH_ATTESTATION_FOR_DIFFERENT_OWNER),
            'asgrim',
            'pie.phar',
            [
                FulcioSigstoreOidExtensions::ISSUER_V2 => 'https://token.actions.githubusercontent.com',
                FulcioSigstoreOidExtensions::SOURCE_REPOSITORY_URI => 'https://github.com/php/pie',
                FulcioSigstoreOidExtensions::SOURCE_REPOSITORY_OWNER_URI => 'https://github.com/php',
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

    public function testDsseEnvelopetSignatureVerificationFailed(): void
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
