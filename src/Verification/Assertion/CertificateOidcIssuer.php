<?php

declare(strict_types=1);

namespace ThePhpFoundation\Attestation\Verification\Assertion;

use ThePhpFoundation\Attestation\Bundle;
use ThePhpFoundation\Attestation\FilenameWithChecksum;
use ThePhpFoundation\Attestation\FulcioSigstoreOidExtensions;
use ThePhpFoundation\Attestation\Verification\Exception\MismatchingExtensionValues;
use Webmozart\Assert\Assert;

use function array_key_exists;
use function openssl_x509_parse;

/**
 * Uses the plain-string Fulcio V1 issuer OID.
 *
 * @internal This is not a public API, so should not be depended upon unless you accept the risk of BC breaks
 */
final class CertificateOidcIssuer implements VerifyBundleCheck
{
    public function __construct(private string $expectedOidcIssuer)
    {
    }

    public function assert(FilenameWithChecksum $file, int $bundleIndex, Bundle $bundle): void
    {
        $attestationCertificateInfo = openssl_x509_parse($bundle->certificate()->decoratedCertificate());
        Assert::isArray($attestationCertificateInfo);
        Assert::keyExists($attestationCertificateInfo, 'extensions');
        Assert::isArray($attestationCertificateInfo['extensions']);

        if (! array_key_exists(FulcioSigstoreOidExtensions::ISSUER_V1, $attestationCertificateInfo['extensions'])) {
            throw MismatchingExtensionValues::from(FulcioSigstoreOidExtensions::ISSUER_V1, $this->expectedOidcIssuer, '(missing)');
        }

        $actualOidcIssuer = $attestationCertificateInfo['extensions'][FulcioSigstoreOidExtensions::ISSUER_V1];
        Assert::stringNotEmpty($actualOidcIssuer);

        if ($actualOidcIssuer !== $this->expectedOidcIssuer) {
            throw MismatchingExtensionValues::from(FulcioSigstoreOidExtensions::ISSUER_V1, $this->expectedOidcIssuer, $actualOidcIssuer);
        }
    }
}
