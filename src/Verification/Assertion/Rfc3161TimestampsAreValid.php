<?php

declare(strict_types=1);

namespace ThePhpFoundation\Attestation\Verification\Assertion;

use DateTimeImmutable;
use DateTimeZone;
use ThePhpFoundation\Attestation\Bundle;
use ThePhpFoundation\Attestation\DsseEnvelope;
use ThePhpFoundation\Attestation\FilenameWithChecksum;
use ThePhpFoundation\Attestation\MessageSignature;
use ThePhpFoundation\Attestation\Verification\Der;
use ThePhpFoundation\Attestation\Verification\Exception\InvalidRfc3161TimestampFormat;
use ThePhpFoundation\Attestation\Verification\Exception\Rfc3161TimestampMessageImprintMismatch;
use ThePhpFoundation\Attestation\Verification\Exception\Rfc3161TimestampVerificationFailed;
use ThePhpFoundation\Attestation\Verification\Exception\TimestampAuthorityCertificateOutsideValidityPeriod;
use ThePhpFoundation\Attestation\Verification\Exception\TimestampAuthorityOutsideValidityPeriod;
use ThePhpFoundation\Attestation\Verification\Exception\TimestampOutsideCertificateValidity;
use ThePhpFoundation\Attestation\Verification\Exception\UnsupportedBundleContent;
use ThePhpFoundation\Attestation\Verification\TrustedRoot;
use Webmozart\Assert\Assert;

use function array_key_exists;
use function file_get_contents;
use function file_put_contents;
use function hash;
use function hash_equals;
use function in_array;
use function openssl_cms_verify;
use function openssl_x509_parse;
use function preg_replace;
use function substr;
use function sys_get_temp_dir;
use function tempnam;
use function unlink;

use const OPENSSL_ENCODING_DER;
use const PKCS7_BINARY;
use const PKCS7_NOVERIFY;

/**
 * @internal This is not a public API, so should not be depended upon unless you accept the risk of BC breaks
 *
 * @link https://www.rfc-editor.org/rfc/rfc3161
 */
final class Rfc3161TimestampsAreValid implements VerifyBundleCheck
{
    private const HASH_ALGORITHM_OIDS = [
        "\x2b\x0e\x03\x02\x1a" => 'sha1',
        "\x60\x86\x48\x01\x65\x03\x04\x02\x01" => 'sha256',
        "\x60\x86\x48\x01\x65\x03\x04\x02\x02" => 'sha384',
        "\x60\x86\x48\x01\x65\x03\x04\x02\x03" => 'sha512',
    ];

    public function __construct(private TrustedRoot $trustedRoot)
    {
    }

    public function assert(FilenameWithChecksum $file, int $bundleIndex, Bundle $bundle): void
    {
        foreach ($bundle->rfc3161Timestamps() as $timestampToken) {
            $genTime = $this->verifyAndExtractGenTime($bundleIndex, $timestampToken, $this->signedContent($bundle));

            $certificateInfo = openssl_x509_parse($bundle->certificate()->decoratedCertificate());
            Assert::isArray($certificateInfo);
            Assert::keyExists($certificateInfo, 'validFrom_time_t');
            Assert::integer($certificateInfo['validFrom_time_t']);
            Assert::keyExists($certificateInfo, 'validTo_time_t');
            Assert::integer($certificateInfo['validTo_time_t']);

            if ($genTime < $certificateInfo['validFrom_time_t'] || $genTime > $certificateInfo['validTo_time_t']) {
                throw TimestampOutsideCertificateValidity::forIndex(
                    $bundleIndex,
                    $genTime,
                    $certificateInfo['validFrom_time_t'],
                    $certificateInfo['validTo_time_t'],
                );
            }
        }
    }

    /** @return non-empty-string */
    private function signedContent(Bundle $bundle): string
    {
        $content = $bundle->content();
        if (! $content instanceof DsseEnvelope && ! $content instanceof MessageSignature) {
            throw UnsupportedBundleContent::new();
        }

        return $content->signature();
    }

    /**
     * @param non-empty-string $timestampToken
     * @param non-empty-string $signedContent
     */
    private function verifyAndExtractGenTime(int $bundleIndex, string $timestampToken, string $signedContent): int
    {
        [$validFor, $tstInfo, $certificateValidFor] = $this->verifyCmsSignatureAgainstKnownTimestampAuthorities($bundleIndex, $timestampToken);

        $messageImprint = $this->extractMessageImprint($bundleIndex, $tstInfo);
        if (! hash_equals(hash($messageImprint['algorithm'], $signedContent, true), $messageImprint['hashedMessage'])) {
            throw Rfc3161TimestampMessageImprintMismatch::forIndex($bundleIndex);
        }

        $genTime = $this->extractGeneralizedTime($bundleIndex, $tstInfo);

        if (
            $genTime < $validFor['start']
            || ($validFor['end'] !== null && $genTime > $validFor['end'])
        ) {
            throw TimestampAuthorityOutsideValidityPeriod::forIndex($bundleIndex, $genTime, $validFor['start'], $validFor['end']);
        }

        if ($genTime < $certificateValidFor['start'] || $genTime > $certificateValidFor['end']) {
            throw TimestampAuthorityCertificateOutsideValidityPeriod::forIndex(
                $bundleIndex,
                $genTime,
                $certificateValidFor['start'],
                $certificateValidFor['end'],
            );
        }

        return $genTime;
    }

    /**
     * @param non-empty-string $timestampResponse
     *
     * @return array{0: array{start: int, end: int|null}, 1: non-empty-string, 2: array{start: int, end: int}}
     */
    private function verifyCmsSignatureAgainstKnownTimestampAuthorities(int $bundleIndex, string $timestampResponse): array
    {
        [$outerTag, $outerContent] = Der::readTlv($timestampResponse, 0);
        Assert::same($outerTag, Der::TAG_SEQUENCE);

        [, , $statusInfoEnd] = Der::readTlv($outerContent, 0);
        $timestampToken      = substr($outerContent, $statusInfoEnd);
        Assert::stringNotEmpty($timestampToken);

        $candidates = $this->trustedRoot->timestampAuthorityCandidates();

        $allCandidateCertsPem = '';
        foreach ($candidates as $candidate) {
            $allCandidateCertsPem .= $candidate['certChainPem'];
        }

        Assert::stringNotEmpty($allCandidateCertsPem);

        $tokenFile   = tempnam(sys_get_temp_dir(), 'sigstore-rfc3161-token-');
        $certsFile   = tempnam(sys_get_temp_dir(), 'sigstore-rfc3161-certs-');
        $signersFile = tempnam(sys_get_temp_dir(), 'sigstore-rfc3161-signers-');
        $tstInfoFile = tempnam(sys_get_temp_dir(), 'sigstore-rfc3161-tstinfo-');
        Assert::notFalse($tokenFile);
        Assert::notFalse($certsFile);
        Assert::notFalse($signersFile);
        Assert::notFalse($tstInfoFile);

        try {
            file_put_contents($tokenFile, $timestampToken);
            file_put_contents($certsFile, $allCandidateCertsPem);

            $verified = openssl_cms_verify(
                $tokenFile,
                PKCS7_NOVERIFY | PKCS7_BINARY,
                $signersFile,
                [],
                $certsFile,
                $tstInfoFile,
                null,
                null,
                OPENSSL_ENCODING_DER,
            );

            if ($verified !== true) {
                throw Rfc3161TimestampVerificationFailed::forIndex($bundleIndex);
            }

            $signersPem = file_get_contents($signersFile);
            Assert::stringNotEmpty($signersPem);
            $signingCertificateDer = Der::bytesFromPem($signersPem);

            $tstInfo = file_get_contents($tstInfoFile);
            Assert::stringNotEmpty($tstInfo);
        } finally {
            unlink($tokenFile);
            unlink($certsFile);
            unlink($signersFile);
            unlink($tstInfoFile);
        }

        foreach ($candidates as $candidate) {
            if (in_array($signingCertificateDer, $candidate['certChainDer'], true)) {
                $signingCertificateInfo = openssl_x509_parse($signersPem);
                Assert::isArray($signingCertificateInfo);
                Assert::keyExists($signingCertificateInfo, 'validFrom_time_t');
                Assert::integer($signingCertificateInfo['validFrom_time_t']);
                Assert::keyExists($signingCertificateInfo, 'validTo_time_t');
                Assert::integer($signingCertificateInfo['validTo_time_t']);

                return [
                    $candidate['validFor'],
                    $tstInfo,
                    [
                        'start' => $signingCertificateInfo['validFrom_time_t'],
                        'end' => $signingCertificateInfo['validTo_time_t'],
                    ],
                ];
            }
        }

        throw Rfc3161TimestampVerificationFailed::forIndex($bundleIndex);
    }

    /**
     * @param non-empty-string $tstInfo
     *
     * @return array{algorithm: non-empty-string, hashedMessage: non-empty-string}
     */
    private function extractMessageImprint(int $bundleIndex, string $tstInfo): array
    {
        [$tag, $content] = Der::readTlv($tstInfo, 0);
        Assert::same($tag, Der::TAG_SEQUENCE);

        $offset = 0;
        for ($i = 0; $i < 2; $i++) {
            [, , $offset] = Der::readTlv($content, $offset);
        }

        [$messageImprintTag, $messageImprintContent] = Der::readTlv($content, $offset);
        Assert::same($messageImprintTag, Der::TAG_SEQUENCE);

        [$algorithmTag, $algorithmContent, $algorithmEnd] = Der::readTlv($messageImprintContent, 0);
        Assert::same($algorithmTag, Der::TAG_SEQUENCE);

        [$oidTag, $oidValue] = Der::readTlv($algorithmContent, 0);
        Assert::same($oidTag, Der::TAG_OBJECT_IDENTIFIER);

        if (! array_key_exists($oidValue, self::HASH_ALGORITHM_OIDS)) {
            throw InvalidRfc3161TimestampFormat::forIndex($bundleIndex);
        }

        [$hashedMessageTag, $hashedMessage] = Der::readTlv($messageImprintContent, $algorithmEnd);
        Assert::same($hashedMessageTag, Der::TAG_OCTET_STRING);
        Assert::stringNotEmpty($hashedMessage);

        return [
            'algorithm' => self::HASH_ALGORITHM_OIDS[$oidValue],
            'hashedMessage' => $hashedMessage,
        ];
    }

    /** @param non-empty-string $tstInfo */
    private function extractGeneralizedTime(int $bundleIndex, string $tstInfo): int
    {
        [$tag, $content] = Der::readTlv($tstInfo, 0);
        Assert::same($tag, Der::TAG_SEQUENCE);

        $offset = 0;
        for ($i = 0; $i < 4; $i++) {
            [, , $offset] = Der::readTlv($content, $offset);
        }

        [$genTimeTag, $genTimeValue] = Der::readTlv($content, $offset);
        Assert::same($genTimeTag, Der::TAG_GENERALIZED_TIME);

        $genTimeValue = preg_replace('/\.\d+Z$/', 'Z', $genTimeValue);
        Assert::stringNotEmpty($genTimeValue);

        $genTime = DateTimeImmutable::createFromFormat('YmdHis\Z', $genTimeValue, new DateTimeZone('UTC'));
        if ($genTime === false) {
            throw InvalidRfc3161TimestampFormat::forIndex($bundleIndex);
        }

        return $genTime->getTimestamp();
    }
}
