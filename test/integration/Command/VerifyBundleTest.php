<?php

declare(strict_types=1);

namespace ThePhpFoundation\IntegrationTest\Attestation\Command;

use PHPUnit\Framework\TestCase;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Tester\CommandTester;
use ThePhpFoundation\Attestation\Command\VerifyBundle;

/** @covers \ThePhpFoundation\Attestation\Command\VerifyBundle */
final class VerifyBundleTest extends TestCase
{
    private const BUNDLE_FIXTURE                         = __DIR__ . '/../../fixture/bundle.json';
    private const PIE_PHAR                               = __DIR__ . '/../../fixture/pie.phar';
    private const PIE_PHAR_DIGEST                        = 'sha256:5ea836df7244a05d62b300a2294b5b6ae10c951f4f6a5e0d2ae2de84541142f0';
    private const OIDC_ISSUER                            = 'https://token.actions.githubusercontent.com';
    private const CERTIFICATE_IDENTITY                   = 'https://github.com/php/pie/.github/workflows/build-phar.yml@refs/tags/1.2.0';
    private const MESSAGE_SIGNATURE_BUNDLE_FIXTURE       = __DIR__ . '/../../fixture/message-signature-bundle.json';
    private const MESSAGE_SIGNATURE_ARTIFACT             = __DIR__ . '/../../fixture/message-signature-artifact.txt';
    private const MESSAGE_SIGNATURE_ARTIFACT_DIGEST      = 'sha256:a0cfc71271d6e278e57cd332ff957c3f7043fdda354c4cbb190a30d56efa01bf';
    private const MESSAGE_SIGNATURE_CERTIFICATE_IDENTITY = 'https://github.com/sigstore-conformance/extremely-dangerous-public-oidc-beacon/.github/workflows/extremely-dangerous-oidc-beacon.yml@refs/heads/main';

    private function commandTester(): CommandTester
    {
        return new CommandTester(new VerifyBundle());
    }

    public function testVerifiesAGenuineBundleSuccessfully(): void
    {
        $tester = $this->commandTester();

        $statusCode = $tester->execute([
            '--bundle' => self::BUNDLE_FIXTURE,
            '--certificate-identity' => self::CERTIFICATE_IDENTITY,
            '--certificate-oidc-issuer' => self::OIDC_ISSUER,
            'artifact' => self::PIE_PHAR,
        ]);

        self::assertSame(Command::SUCCESS, $statusCode);
        self::assertStringContainsString('Verified', $tester->getDisplay());
    }

    public function testVerifiesAGenuineBundleSuccessfullyInDigestMode(): void
    {
        $tester = $this->commandTester();

        $statusCode = $tester->execute([
            '--bundle' => self::BUNDLE_FIXTURE,
            '--certificate-identity' => self::CERTIFICATE_IDENTITY,
            '--certificate-oidc-issuer' => self::OIDC_ISSUER,
            'artifact' => self::PIE_PHAR_DIGEST,
        ]);

        self::assertSame(Command::SUCCESS, $statusCode);
        self::assertStringContainsString('Verified', $tester->getDisplay());
    }

    public function testVerifiesAMessageSignatureBundleSuccessfully(): void
    {
        $tester = $this->commandTester();

        $statusCode = $tester->execute([
            '--bundle' => self::MESSAGE_SIGNATURE_BUNDLE_FIXTURE,
            '--certificate-identity' => self::MESSAGE_SIGNATURE_CERTIFICATE_IDENTITY,
            '--certificate-oidc-issuer' => self::OIDC_ISSUER,
            'artifact' => self::MESSAGE_SIGNATURE_ARTIFACT,
        ]);

        self::assertSame(Command::SUCCESS, $statusCode);
        self::assertStringContainsString('Verified', $tester->getDisplay());
    }

    public function testVerifiesAMessageSignatureBundleFromTheDigestAloneInDigestMode(): void
    {
        $tester = $this->commandTester();

        $statusCode = $tester->execute([
            '--bundle' => self::MESSAGE_SIGNATURE_BUNDLE_FIXTURE,
            '--certificate-identity' => self::MESSAGE_SIGNATURE_CERTIFICATE_IDENTITY,
            '--certificate-oidc-issuer' => self::OIDC_ISSUER,
            'artifact' => self::MESSAGE_SIGNATURE_ARTIFACT_DIGEST,
        ]);

        self::assertSame(Command::SUCCESS, $statusCode);
    }

    public function testFailsWhenCertificateOidcIssuerDoesNotMatch(): void
    {
        $tester = $this->commandTester();

        $statusCode = $tester->execute([
            '--bundle' => self::BUNDLE_FIXTURE,
            '--certificate-identity' => self::CERTIFICATE_IDENTITY,
            '--certificate-oidc-issuer' => 'https://wrong-issuer.example.com',
            'artifact' => self::PIE_PHAR,
        ]);

        self::assertSame(Command::FAILURE, $statusCode);
        self::assertStringContainsString('mismatch', $tester->getDisplay());
    }

    public function testFailsWhenCertificateIdentityDoesNotMatch(): void
    {
        $tester = $this->commandTester();

        $statusCode = $tester->execute([
            '--bundle' => self::BUNDLE_FIXTURE,
            '--certificate-identity' => 'https://github.com/some-other-org/some-other-repo/.github/workflows/build.yml@refs/heads/main',
            '--certificate-oidc-issuer' => self::OIDC_ISSUER,
            'artifact' => self::PIE_PHAR,
        ]);

        self::assertSame(Command::FAILURE, $statusCode);
        self::assertStringContainsString('identity mismatch', $tester->getDisplay());
    }

    public function testFailsWhenBundleFileDoesNotExist(): void
    {
        $tester = $this->commandTester();

        $statusCode = $tester->execute([
            '--bundle' => self::BUNDLE_FIXTURE . '.does-not-exist',
            '--certificate-identity' => self::CERTIFICATE_IDENTITY,
            '--certificate-oidc-issuer' => self::OIDC_ISSUER,
            'artifact' => self::PIE_PHAR,
        ]);

        self::assertSame(Command::FAILURE, $statusCode);
        self::assertStringContainsString('does not exist or is not readable', $tester->getDisplay());
    }
}
