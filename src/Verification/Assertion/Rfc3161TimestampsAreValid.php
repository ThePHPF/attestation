<?php

declare(strict_types=1);

namespace ThePhpFoundation\Attestation\Verification\Assertion;

use DateTimeImmutable;
use DateTimeZone;
use ThePhpFoundation\Attestation\Bundle;
use ThePhpFoundation\Attestation\FilenameWithChecksum;
use ThePhpFoundation\Attestation\Verification\Der;
use ThePhpFoundation\Attestation\Verification\Exception\InvalidRfc3161TimestampFormat;
use ThePhpFoundation\Attestation\Verification\Exception\Rfc3161TimestampVerificationFailed;
use ThePhpFoundation\Attestation\Verification\Exception\TimestampAuthorityOutsideValidityPeriod;
use ThePhpFoundation\Attestation\Verification\Exception\TimestampOutsideCertificateValidity;
use ThePhpFoundation\Attestation\Verification\TrustedRoot;
use Webmozart\Assert\Assert;

use function file_get_contents;
use function file_put_contents;
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

/** @link https://www.rfc-editor.org/rfc/rfc3161 */
final class Rfc3161TimestampsAreValid implements VerifyBundleCheck
{
    public function __construct(private TrustedRoot $trustedRoot)
    {
    }

    public function assert(FilenameWithChecksum $file, int $bundleIndex, Bundle $bundle): void
    {
        foreach ($bundle->rfc3161Timestamps() as $timestampToken) {
            $genTime = $this->verifyAndExtractGenTime($bundleIndex, $timestampToken);

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

    /** @param non-empty-string $timestampToken */
    private function verifyAndExtractGenTime(int $bundleIndex, string $timestampToken): int
    {
        [$validFor, $tstInfo] = $this->verifyCmsSignatureAgainstKnownTimestampAuthorities($bundleIndex, $timestampToken);

        $genTime = $this->extractGeneralizedTime($bundleIndex, $tstInfo);

        if (
            $genTime < $validFor['start']
            || ($validFor['end'] !== null && $genTime > $validFor['end'])
        ) {
            throw TimestampAuthorityOutsideValidityPeriod::forIndex($bundleIndex, $genTime, $validFor['start'], $validFor['end']);
        }

        return $genTime;
    }

    /**
     * @param non-empty-string $timestampResponse
     *
     * @return array{0: array{start: int, end: int|null}, 1: non-empty-string} [matched TSA's validFor, TSTInfo DER bytes]
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
                return [$candidate['validFor'], $tstInfo];
            }
        }

        throw Rfc3161TimestampVerificationFailed::forIndex($bundleIndex);
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
