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
    private const BUNDLE_FIXTURE       = __DIR__ . '/../../fixture/bundle.json';
    private const PIE_PHAR             = __DIR__ . '/../../fixture/pie.phar';
    private const OIDC_ISSUER          = 'https://token.actions.githubusercontent.com';
    private const CERTIFICATE_IDENTITY = 'https://github.com/php/pie/.github/workflows/build-phar.yml@refs/tags/1.2.0';

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
