<?php

declare(strict_types=1);

namespace ThePHPFoundation\IntegrationTest\Attestation;

use PHPUnit\Framework\TestCase;
use ThePHPFoundation\Attestation\FilenameWithChecksum;
use ThePHPFoundation\Attestation\Problem\MissingAttestation;
use ThePHPFoundation\Attestation\VerifyAttestationWithOpenSsl;

/** @covers \ThePHPFoundation\Attestation\VerifyAttestationWithOpenSsl */
class VerifyAttestationWithOpenSslTest extends TestCase
{
    private const PIE_PHAR = __DIR__ . '/../fixture/pie.phar';

    private VerifyAttestationWithOpenSsl $verifier;

    public function setUp(): void
    {
        $this->verifier = VerifyAttestationWithOpenSsl::factory();
    }

    public function testSuccessfulVerification(): void
    {
        $this->expectNotToPerformAssertions();
        $this->verifier->verify(FilenameWithChecksum::fromFilename(self::PIE_PHAR));
    }

    public function testMissingAttestation(): void
    {
        $this->expectException(MissingAttestation::class);
        $this->verifier->verify(FilenameWithChecksum::fromFilename(__FILE__));
    }

    // @todo bunch more tests
}
