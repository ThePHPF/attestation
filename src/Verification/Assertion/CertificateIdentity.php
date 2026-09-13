<?php

declare(strict_types=1);

namespace ThePhpFoundation\Attestation\Verification\Assertion;

use ThePhpFoundation\Attestation\Bundle;
use ThePhpFoundation\Attestation\FilenameWithChecksum;
use ThePhpFoundation\Attestation\Verification\Exception\CertificateIdentityMismatch;
use Webmozart\Assert\Assert;

use function array_map;
use function explode;
use function in_array;
use function openssl_x509_parse;
use function trim;

/** @internal This is not a public API, so should not be depended upon unless you accept the risk of BC breaks */
final class CertificateIdentity implements VerifyBundleCheck
{
    public function __construct(private string $expectedCertificateIdentity)
    {
    }

    public function assert(FilenameWithChecksum $file, int $bundleIndex, Bundle $bundle): void
    {
        $attestationCertificateInfo = openssl_x509_parse($bundle->certificate()->decoratedCertificate());
        Assert::isArray($attestationCertificateInfo);
        Assert::keyExists($attestationCertificateInfo, 'extensions');
        Assert::isArray($attestationCertificateInfo['extensions']);
        Assert::keyExists($attestationCertificateInfo['extensions'], 'subjectAltName');
        Assert::stringNotEmpty($attestationCertificateInfo['extensions']['subjectAltName']);

        $subjectAltName = $attestationCertificateInfo['extensions']['subjectAltName'];

        $identities = array_map(
            static function (string $entry): string {
                $parts = explode(':', trim($entry), 2);

                return $parts[1] ?? $parts[0];
            },
            explode(',', $subjectAltName),
        );

        if (! in_array($this->expectedCertificateIdentity, $identities, true)) {
            throw CertificateIdentityMismatch::from($this->expectedCertificateIdentity, $subjectAltName);
        }
    }
}
