<?php

declare(strict_types=1);

namespace ThePhpFoundation\Attestation\Verification\Assertion;

use ThePhpFoundation\Attestation\Bundle;
use ThePhpFoundation\Attestation\FilenameWithChecksum;
use ThePhpFoundation\Attestation\Verification\Exception\IssuerCertificateVerificationFailed;
use ThePhpFoundation\Attestation\Verification\Exception\NoIssuerCertificateInTrustedRoot;
use ThePhpFoundation\Attestation\Verification\TrustedRoot;
use Webmozart\Assert\Assert;

use function is_array;
use function openssl_x509_parse;
use function openssl_x509_verify;

final class CertificateSignedByTrustedRoot implements VerifyBundleCheck
{
    private TrustedRoot $trustedRoot;

    public function __construct(TrustedRoot $trustedRoot)
    {
        $this->trustedRoot = $trustedRoot;
    }

    public function assert(FilenameWithChecksum $file, int $bundleIndex, Bundle $bundle): void
    {
        $attestationCertificateInfo = openssl_x509_parse($bundle->certificate()->decoratedCertificate());
        Assert::isArray($attestationCertificateInfo);
        Assert::keyExists($attestationCertificateInfo, 'issuer');
        if (is_array($attestationCertificateInfo['issuer'])) {
            Assert::allStringNotEmpty($attestationCertificateInfo['issuer']);
        } else {
            Assert::stringNotEmpty($attestationCertificateInfo['issuer']);
        }

        $caCertificate = $this->trustedRoot->resolveCertificateAuthorityCertificate($attestationCertificateInfo['issuer']);
        if ($caCertificate === null) {
            /** @psalm-suppress MixedArgument */
            throw NoIssuerCertificateInTrustedRoot::fromIssuer($attestationCertificateInfo['issuer']);
        }

        if (openssl_x509_verify($bundle->certificate()->decoratedCertificate(), $caCertificate->decoratedCertificate()) !== 1) {
            /** @psalm-suppress MixedArgument */
            throw IssuerCertificateVerificationFailed::fromIssuer($attestationCertificateInfo['issuer']);
        }
    }
}
