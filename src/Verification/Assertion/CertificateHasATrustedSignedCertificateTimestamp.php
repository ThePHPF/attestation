<?php

declare(strict_types=1);

namespace ThePhpFoundation\Attestation\Verification\Assertion;

use ThePhpFoundation\Attestation\Bundle;
use ThePhpFoundation\Attestation\FilenameWithChecksum;
use ThePhpFoundation\Attestation\Verification\Der;
use ThePhpFoundation\Attestation\Verification\Exception\NoIssuerCertificateInTrustedRoot;
use ThePhpFoundation\Attestation\Verification\Exception\SignedCertificateTimestampVerificationFailed;
use ThePhpFoundation\Attestation\Verification\Exception\UnsupportedSignedCertificateTimestampAlgorithm;
use ThePhpFoundation\Attestation\Verification\Exception\UntrustedCertificateTransparencyLogKey;
use ThePhpFoundation\Attestation\Verification\TransparencyLogSignature;
use ThePhpFoundation\Attestation\Verification\TrustedRoot;
use Webmozart\Assert\Assert;

use function hash;
use function is_array;
use function openssl_pkey_get_details;
use function openssl_pkey_get_public;
use function openssl_x509_parse;
use function ord;
use function pack;
use function strlen;
use function substr;

/**
 * @internal This is not a public API, so should not be depended upon unless you accept the risk of BC breaks
 *
 * @phpstan-type SignedCertificateTimestampData array{
 *     logId: non-empty-string,
 *     timestampBytes: non-empty-string,
 *     extensions: string,
 *     hashAlgorithm: int,
 *     signatureAlgorithm: int,
 *     signature: non-empty-string
 * }
 */
final class CertificateHasATrustedSignedCertificateTimestamp implements VerifyBundleCheck
{
    /** @link https://www.rfc-editor.org/rfc/rfc6962#section-3.3 */
    private const CT_PRECERT_SCTS_EXTENSION_OID_DER = "\x2b\x06\x01\x04\x01\xd6\x79\x02\x04\x02";

    /** @link https://www.rfc-editor.org/rfc/rfc5246#section-7.4.1.4.1 */
    private const CT_HASH_ALGORITHM_SHA256     = 4;
    private const CT_SIGNATURE_ALGORITHM_ECDSA = 3;

    /** @link https://www.rfc-editor.org/rfc/rfc6962#section-3.2 */
    private const CT_ENTRY_TYPE_PRECERT = "\x00\x01";

    public function __construct(private TrustedRoot $trustedRoot)
    {
    }

    public function assert(FilenameWithChecksum $file, int $bundleIndex, Bundle $bundle): void
    {
        $certificateDer              = $bundle->certificate()->derEncodedBytes();
        $signedCertificateTimestamps = $this->extractSignedCertificateTimestamps($certificateDer);

        $trustedLogIdMatched   = false;
        $precertTbsCertificate = null;
        $issuerKeyHash         = null;

        foreach ($signedCertificateTimestamps as $signedCertificateTimestamp) {
            if (! $this->trustedRoot->isCertificateTransparencyLogIdTrusted($signedCertificateTimestamp['logId'])) {
                continue;
            }

            $trustedLogIdMatched = true;

            if (
                $signedCertificateTimestamp['hashAlgorithm'] !== self::CT_HASH_ALGORITHM_SHA256
                || $signedCertificateTimestamp['signatureAlgorithm'] !== self::CT_SIGNATURE_ALGORITHM_ECDSA
            ) {
                throw UnsupportedSignedCertificateTimestampAlgorithm::fromAlgorithms(
                    $signedCertificateTimestamp['hashAlgorithm'],
                    $signedCertificateTimestamp['signatureAlgorithm'],
                );
            }

            $precertTbsCertificate ??= $this->buildPrecertTbsCertificate($certificateDer);
            $issuerKeyHash         ??= $this->resolveIssuerSubjectPublicKeyInfoHash($bundle);

            $transparencyLogKey = $this->trustedRoot->resolveCertificateTransparencyLogPublicKey($signedCertificateTimestamp['logId']);
            $signedContent      = $this->buildDigitallySignedContent($signedCertificateTimestamp, $issuerKeyHash, $precertTbsCertificate);

            if (TransparencyLogSignature::verify($transparencyLogKey, $signedContent, $signedCertificateTimestamp['signature'])) {
                return;
            }
        }

        throw $trustedLogIdMatched ? SignedCertificateTimestampVerificationFailed::new() : UntrustedCertificateTransparencyLogKey::new();
    }

    /** @return non-empty-list<SignedCertificateTimestampData> */
    private function extractSignedCertificateTimestamps(string $certificateDer): array
    {
        [$certTag, $certContent] = Der::readTlv($certificateDer, 0);
        Assert::same($certTag, Der::TAG_SEQUENCE);

        [$tbsTag, $tbsContent] = Der::readTlv($certContent, 0);
        Assert::same($tbsTag, Der::TAG_SEQUENCE);

        $extensionsBlock = null;
        $offset          = 0;
        while ($offset < strlen($tbsContent)) {
            [$fieldTag, $fieldValue, $offset] = Der::readTlv($tbsContent, $offset);
            if ($fieldTag !== Der::TAG_CONTEXT_EXTENSIONS) {
                continue;
            }

            $extensionsBlock = $fieldValue;
        }

        Assert::stringNotEmpty($extensionsBlock);

        [$extSeqTag, $extSeqContent] = Der::readTlv($extensionsBlock, 0);
        Assert::same($extSeqTag, Der::TAG_SEQUENCE);

        $sctExtensionValue = null;
        $offset            = 0;
        while ($offset < strlen($extSeqContent)) {
            [$extTag, $extContent, $offset] = Der::readTlv($extSeqContent, $offset);
            if ($extTag !== Der::TAG_SEQUENCE) {
                continue;
            }

            [$oidTag, $oidValue, $innerOffset] = Der::readTlv($extContent, 0);
            Assert::same($oidTag, Der::TAG_OBJECT_IDENTIFIER);
            if ($oidValue !== self::CT_PRECERT_SCTS_EXTENSION_OID_DER) {
                continue;
            }

            [$nextTag, $nextValue, $innerOffset] = Der::readTlv($extContent, $innerOffset);
            if ($nextTag === Der::TAG_BOOLEAN) {
                [$nextTag, $nextValue] = Der::readTlv($extContent, $innerOffset);
            }

            Assert::same($nextTag, Der::TAG_OCTET_STRING);
            $sctExtensionValue = $nextValue;
        }

        Assert::stringNotEmpty($sctExtensionValue);

        [$innerOctetStringTag, $sctList] = Der::readTlv($sctExtensionValue, 0);
        Assert::same($innerOctetStringTag, Der::TAG_OCTET_STRING);
        Assert::true(strlen($sctList) >= 2);

        $signedCertificateTimestamps = [];
        $offset                      = 2; // Skip the 2-byte total-length prefix of the SignedCertificateTimestampList.
        while ($offset < strlen($sctList)) {
            Assert::true($offset + 2 <= strlen($sctList));
            $sctLength = (ord($sctList[$offset]) << 8) | ord($sctList[$offset + 1]);
            $offset   += 2;

            Assert::true($offset + $sctLength <= strlen($sctList));
            $sct     = substr($sctList, $offset, $sctLength);
            $offset += $sctLength;

            $signedCertificateTimestamps[] = $this->parseSignedCertificateTimestamp($sct);
        }

        Assert::isNonEmptyList($signedCertificateTimestamps);

        return $signedCertificateTimestamps;
    }

    /** @return SignedCertificateTimestampData */
    private function parseSignedCertificateTimestamp(string $sct): array
    {
        Assert::true(strlen($sct) >= 43);

        $logId = substr($sct, 1, 32);
        Assert::stringNotEmpty($logId);

        $timestampBytes = substr($sct, 33, 8);
        Assert::same(strlen($timestampBytes), 8);

        $offset           = 41;
        $extensionsLength = (ord($sct[$offset]) << 8) | ord($sct[$offset + 1]);
        $offset          += 2;

        Assert::true($offset + $extensionsLength + 4 <= strlen($sct));
        $extensions = substr($sct, $offset, $extensionsLength);
        $offset    += $extensionsLength;

        $hashAlgorithm      = ord($sct[$offset]);
        $signatureAlgorithm = ord($sct[$offset + 1]);
        $offset            += 2;

        $signatureLength = (ord($sct[$offset]) << 8) | ord($sct[$offset + 1]);
        $offset         += 2;

        Assert::same($offset + $signatureLength, strlen($sct));
        $signature = substr($sct, $offset, $signatureLength);
        Assert::stringNotEmpty($signature);

        return [
            'logId' => $logId,
            'timestampBytes' => $timestampBytes,
            'extensions' => $extensions,
            'hashAlgorithm' => $hashAlgorithm,
            'signatureAlgorithm' => $signatureAlgorithm,
            'signature' => $signature,
        ];
    }

    private function buildPrecertTbsCertificate(string $certificateDer): string
    {
        [$certTag, $certContent] = Der::readTlv($certificateDer, 0);
        Assert::same($certTag, Der::TAG_SEQUENCE);

        [$tbsTag, $tbsContent] = Der::readTlv($certContent, 0);
        Assert::same($tbsTag, Der::TAG_SEQUENCE);

        $extensionsFieldOffset = null;
        $extensionsFieldValue  = null;
        $offset                = 0;
        while ($offset < strlen($tbsContent)) {
            $fieldStart                       = $offset;
            [$fieldTag, $fieldValue, $offset] = Der::readTlv($tbsContent, $offset);
            if ($fieldTag !== Der::TAG_CONTEXT_EXTENSIONS) {
                continue;
            }

            $extensionsFieldOffset = $fieldStart;
            $extensionsFieldValue  = $fieldValue;
        }

        Assert::notNull($extensionsFieldOffset);
        Assert::stringNotEmpty($extensionsFieldValue);

        [$extSeqTag, $extSeqContent] = Der::readTlv($extensionsFieldValue, 0);
        Assert::same($extSeqTag, Der::TAG_SEQUENCE);

        $remainingExtensions = '';
        $offset              = 0;
        while ($offset < strlen($extSeqContent)) {
            $extensionStart                 = $offset;
            [$extTag, $extContent, $offset] = Der::readTlv($extSeqContent, $offset);
            Assert::same($extTag, Der::TAG_SEQUENCE);

            [$oidTag, $oidValue] = Der::readTlv($extContent, 0);
            Assert::same($oidTag, Der::TAG_OBJECT_IDENTIFIER);

            if ($oidValue === self::CT_PRECERT_SCTS_EXTENSION_OID_DER) {
                continue;
            }

            $remainingExtensions .= substr($extSeqContent, $extensionStart, $offset - $extensionStart);
        }

        $rebuiltExtensionsField = Der::writeTlv(Der::TAG_CONTEXT_EXTENSIONS, Der::writeTlv(Der::TAG_SEQUENCE, $remainingExtensions));

        $rebuiltTbsContent = substr($tbsContent, 0, $extensionsFieldOffset) . $rebuiltExtensionsField;

        return Der::writeTlv(Der::TAG_SEQUENCE, $rebuiltTbsContent);
    }

    /** @return non-empty-string SHA-256 of the issuer certificate's SubjectPublicKeyInfo, in raw bytes */
    private function resolveIssuerSubjectPublicKeyInfoHash(Bundle $bundle): string
    {
        $attestationCertificateInfo = openssl_x509_parse($bundle->certificate()->decoratedCertificate());
        Assert::isArray($attestationCertificateInfo);
        Assert::keyExists($attestationCertificateInfo, 'issuer');
        if (is_array($attestationCertificateInfo['issuer'])) {
            Assert::allStringNotEmpty($attestationCertificateInfo['issuer']);
        } else {
            Assert::stringNotEmpty($attestationCertificateInfo['issuer']);
        }

        /** @psalm-suppress MixedArgument */
        $issuerCertificate = $this->trustedRoot->resolveCertificateAuthorityCertificate($attestationCertificateInfo['issuer']);
        if ($issuerCertificate === null) {
            /** @psalm-suppress MixedArgument */
            throw NoIssuerCertificateInTrustedRoot::fromIssuer($attestationCertificateInfo['issuer']);
        }

        $issuerPublicKey = openssl_pkey_get_public($issuerCertificate->decoratedCertificate());
        Assert::notFalse($issuerPublicKey);

        $issuerPublicKeyDetails = openssl_pkey_get_details($issuerPublicKey);
        Assert::isArray($issuerPublicKeyDetails);
        Assert::keyExists($issuerPublicKeyDetails, 'key');
        Assert::stringNotEmpty($issuerPublicKeyDetails['key']);

        return hash('sha256', Der::bytesFromPublicKeyPem($issuerPublicKeyDetails['key']), true);
    }

    /**
     * @param SignedCertificateTimestampData $signedCertificateTimestamp
     *
     * @return non-empty-string the RFC 6962 §3.2 "digitally-signed" byte sequence for a precertificate SCT
     */
    private function buildDigitallySignedContent(array $signedCertificateTimestamp, string $issuerKeyHash, string $precertTbsCertificate): string
    {
        return "\x00" // version = v1
            . "\x00" // signature_type = certificate_timestamp
            . $signedCertificateTimestamp['timestampBytes']
            . self::CT_ENTRY_TYPE_PRECERT
            . $issuerKeyHash
            . self::encodeUint24(strlen($precertTbsCertificate)) . $precertTbsCertificate
            . pack('n', strlen($signedCertificateTimestamp['extensions'])) . $signedCertificateTimestamp['extensions'];
    }

    private static function encodeUint24(int $value): string
    {
        return substr(pack('N', $value), 1);
    }
}
