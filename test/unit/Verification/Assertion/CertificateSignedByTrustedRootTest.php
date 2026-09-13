<?php

declare(strict_types=1);

namespace ThePhpFoundation\UnitTest\Attestation\Verification\Assertion;

use OpenSSLAsymmetricKey;
use OpenSSLCertificateSigningRequest;
use PHPUnit\Framework\TestCase;
use ThePhpFoundation\Attestation\Bundle;
use ThePhpFoundation\Attestation\FilenameWithChecksum;
use ThePhpFoundation\Attestation\Verification\Assertion\CertificateSignedByTrustedRoot;
use ThePhpFoundation\Attestation\Verification\Der;
use ThePhpFoundation\Attestation\Verification\Exception\IssuerCertificateVerificationFailed;
use ThePhpFoundation\Attestation\Verification\Exception\NoIssuerCertificateInTrustedRoot;
use ThePhpFoundation\Attestation\Verification\TrustedRoot;
use Webmozart\Assert\Assert;

use function base64_encode;
use function file_exists;
use function file_get_contents;
use function file_put_contents;
use function json_decode;
use function json_encode;
use function openssl_csr_new;
use function openssl_csr_sign;
use function openssl_pkey_new;
use function openssl_x509_export;
use function sys_get_temp_dir;
use function tempnam;
use function unlink;

use const OPENSSL_KEYTYPE_EC;

/** @covers \ThePhpFoundation\Attestation\Verification\Assertion\CertificateSignedByTrustedRoot */
final class CertificateSignedByTrustedRootTest extends TestCase
{
    private const PRODUCTION_TRUSTED_ROOT = __DIR__ . '/../../../../resources/trusted-root.jsonl';
    private const BUNDLE_FIXTURE          = __DIR__ . '/../../../fixture/bundle.json';

    /** @var list<string> */
    private static array $temporaryFiles = [];

    protected function tearDown(): void
    {
        foreach (self::$temporaryFiles as $path) {
            if (! file_exists($path)) {
                continue;
            }

            unlink($path);
        }

        self::$temporaryFiles = [];
    }

    private static function bundle(): Bundle
    {
        $contents = file_get_contents(self::BUNDLE_FIXTURE);
        Assert::stringNotEmpty($contents);

        /** @var array<array-key, mixed> $decoded */
        $decoded = json_decode($contents, true);

        return Bundle::fromBundle($decoded);
    }

    private static function trustedRootWithWrongCaCertificateForSameIssuerSubject(): TrustedRoot
    {
        $opensslConfigPath = tempnam(sys_get_temp_dir(), 'sigstore-openssl-config-');
        Assert::notFalse($opensslConfigPath);
        self::$temporaryFiles[] = $opensslConfigPath;
        file_put_contents($opensslConfigPath, "[req]\ndistinguished_name = req_distinguished_name\n[req_distinguished_name]\n");

        $privateKey = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
        Assert::isInstanceOf($privateKey, OpenSSLAsymmetricKey::class);

        $csr = openssl_csr_new(
            ['O' => 'sigstore.dev', 'CN' => 'sigstore-intermediate'],
            $privateKey,
            ['digest_alg' => 'sha256', 'config' => $opensslConfigPath],
        );
        Assert::isInstanceOf($csr, OpenSSLCertificateSigningRequest::class);
        Assert::isInstanceOf($privateKey, OpenSSLAsymmetricKey::class);

        $certificate = openssl_csr_sign($csr, null, $privateKey, 365, ['digest_alg' => 'sha256', 'config' => $opensslConfigPath]);
        Assert::notFalse($certificate);

        openssl_x509_export($certificate, $pem);
        Assert::stringNotEmpty($pem);

        $der = Der::bytesFromPem($pem);

        $trustedRootPath = tempnam(sys_get_temp_dir(), 'sigstore-fake-trusted-root-');
        Assert::notFalse($trustedRootPath);
        self::$temporaryFiles[] = $trustedRootPath;
        file_put_contents($trustedRootPath, (string) json_encode([
            'mediaType' => 'application/vnd.dev.sigstore.trustedroot+json;version=0.1',
            'certificateAuthorities' => [
                [
                    'subject' => ['organization' => 'sigstore.dev', 'commonName' => 'sigstore-intermediate'],
                    'certChain' => ['certificates' => [['rawBytes' => base64_encode($der)]]],
                ],
            ],
        ]));

        return new TrustedRoot($trustedRootPath);
    }

    private static function trustedRootWithNoCertificateAuthorities(): TrustedRoot
    {
        $trustedRootPath = tempnam(sys_get_temp_dir(), 'sigstore-empty-trusted-root-');
        Assert::notFalse($trustedRootPath);
        self::$temporaryFiles[] = $trustedRootPath;
        file_put_contents($trustedRootPath, (string) json_encode([
            'mediaType' => 'application/vnd.dev.sigstore.trustedroot+json;version=0.1',
            'certificateAuthorities' => [],
        ]));

        return new TrustedRoot($trustedRootPath);
    }

    public function testAcceptsACertificateSignedByATrustedCertificateAuthority(): void
    {
        $check = new CertificateSignedByTrustedRoot(new TrustedRoot(self::PRODUCTION_TRUSTED_ROOT));

        $this->expectNotToPerformAssertions();
        $check->assert(FilenameWithChecksum::fromFilenameAndChecksum('irrelevant', 'irrelevant'), 0, self::bundle());
    }

    public function testRejectsACertificateWhoseIssuerIsNotInTheTrustedRoot(): void
    {
        $check = new CertificateSignedByTrustedRoot(self::trustedRootWithNoCertificateAuthorities());

        $this->expectException(NoIssuerCertificateInTrustedRoot::class);
        $check->assert(FilenameWithChecksum::fromFilenameAndChecksum('irrelevant', 'irrelevant'), 0, self::bundle());
    }

    public function testRejectsACertificateThatWasNotActuallySignedByTheMatchedCertificateAuthority(): void
    {
        $check = new CertificateSignedByTrustedRoot(self::trustedRootWithWrongCaCertificateForSameIssuerSubject());

        $this->expectException(IssuerCertificateVerificationFailed::class);
        $check->assert(FilenameWithChecksum::fromFilenameAndChecksum('irrelevant', 'irrelevant'), 0, self::bundle());
    }
}
