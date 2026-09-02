<?php

declare(strict_types=1);

namespace ThePhpFoundation\Attestation\Verification;

use ThePhpFoundation\Attestation\PemCertificate;
use ThePhpFoundation\Attestation\PemPublicKey;
use ThePhpFoundation\Attestation\Verification\Exception\NoTransparencyLogKeyInTrustedRoot;
use ThePhpFoundation\Attestation\Verification\Exception\UnsupportedTransparencyLogKeyAlgorithm;
use Webmozart\Assert\Assert;

use function array_key_exists;
use function base64_decode;
use function bin2hex;
use function explode;
use function file_get_contents;
use function hash_equals;
use function in_array;
use function is_array;
use function is_string;
use function json_decode;
use function openssl_x509_parse;
use function strtotime;
use function trim;

/**
 * @internal This is not a public API, so should not be depended upon unless you accept the risk of BC breaks
 *
 * @phpstan-type TransparencyLogKey array{publicKey: PemPublicKey, keyId: non-empty-string, keyDetails: non-empty-string, validFor: array{start: int, end: int|null}}
 */
final class TrustedRoot
{
    public const KEY_DETAILS_ECDSA_P256_SHA_256 = 'PKIX_ECDSA_P256_SHA_256';
    public const KEY_DETAILS_ED25519            = 'PKIX_ED25519';

    private const SUPPORTED_TRANSPARENCY_LOG_KEY_DETAILS = [
        self::KEY_DETAILS_ECDSA_P256_SHA_256,
        self::KEY_DETAILS_ED25519,
    ];

    /** @param non-empty-string $trustedRootFilePath */
    public function __construct(private string $trustedRootFilePath)
    {
        Assert::fileExists($trustedRootFilePath);
    }

    /**
     * @param non-empty-string $logId
     *
     * @return TransparencyLogKey
     */
    public function resolveTransparencyLogPublicKey(string $logId): array
    {
        foreach ($this->parseDocuments() as $decoded) {
            if (
                ! is_array($decoded)
                || ! array_key_exists('tlogs', $decoded)
                || ! is_array($decoded['tlogs'])
            ) {
                continue;
            }

            /** @var mixed $tlog */
            foreach ($decoded['tlogs'] as $tlog) {
                if (
                    ! is_array($tlog)
                    || ! array_key_exists('logId', $tlog)
                    || ! is_array($tlog['logId'])
                    || ! array_key_exists('keyId', $tlog['logId'])
                    || ! is_string($tlog['logId']['keyId'])
                    || $tlog['logId']['keyId'] === ''
                    || ! array_key_exists('publicKey', $tlog)
                    || ! is_array($tlog['publicKey'])
                    || ! array_key_exists('rawBytes', $tlog['publicKey'])
                    || ! is_string($tlog['publicKey']['rawBytes'])
                    || $tlog['publicKey']['rawBytes'] === ''
                    || ! array_key_exists('keyDetails', $tlog['publicKey'])
                    || ! is_string($tlog['publicKey']['keyDetails'])
                    || $tlog['publicKey']['keyDetails'] === ''
                ) {
                    continue;
                }

                $tlogKeyId = base64_decode($tlog['logId']['keyId']);
                if ($tlogKeyId === '' || ! hash_equals($logId, $tlogKeyId)) {
                    continue;
                }

                if (! in_array($tlog['publicKey']['keyDetails'], self::SUPPORTED_TRANSPARENCY_LOG_KEY_DETAILS, true)) {
                    throw UnsupportedTransparencyLogKeyAlgorithm::fromKeyDetails($tlog['publicKey']['keyDetails']);
                }

                Assert::keyExists($tlog['publicKey'], 'validFor');
                Assert::isArray($tlog['publicKey']['validFor']);
                Assert::keyExists($tlog['publicKey']['validFor'], 'start');
                Assert::stringNotEmpty($tlog['publicKey']['validFor']['start']);
                $validForStart = strtotime($tlog['publicKey']['validFor']['start']);
                Assert::notFalse($validForStart);

                $validForEnd = null;
                if (
                    array_key_exists('end', $tlog['publicKey']['validFor'])
                    && $tlog['publicKey']['validFor']['end'] !== null
                ) {
                    Assert::stringNotEmpty($tlog['publicKey']['validFor']['end']);
                    $validForEnd = strtotime($tlog['publicKey']['validFor']['end']);
                    Assert::notFalse($validForEnd);
                }

                return [
                    'publicKey' => PemPublicKey::fromBase64EncodedDerBytes($tlog['publicKey']['rawBytes']),
                    'keyId' => $tlogKeyId,
                    'keyDetails' => $tlog['publicKey']['keyDetails'],
                    'validFor' => [
                        'start' => $validForStart,
                        'end' => $validForEnd,
                    ],
                ];
            }
        }

        throw NoTransparencyLogKeyInTrustedRoot::fromLogId(bin2hex($logId));
    }

    /** @return list<array{certChainPem: non-empty-string, certChainDer: non-empty-list<non-empty-string>, validFor: array{start: int, end: int|null}}> */
    public function timestampAuthorityCandidates(): array
    {
        $candidates = [];
        foreach ($this->parseDocuments() as $decoded) {
            if (
                ! is_array($decoded)
                || ! array_key_exists('timestampAuthorities', $decoded)
                || ! is_array($decoded['timestampAuthorities'])
            ) {
                continue;
            }

            /** @var mixed $timestampAuthority */
            foreach ($decoded['timestampAuthorities'] as $timestampAuthority) {
                if (
                    ! is_array($timestampAuthority)
                    || ! array_key_exists('certChain', $timestampAuthority)
                    || ! is_array($timestampAuthority['certChain'])
                    || ! array_key_exists('certificates', $timestampAuthority['certChain'])
                    || ! is_array($timestampAuthority['certChain']['certificates'])
                    || ! array_key_exists('validFor', $timestampAuthority)
                    || ! is_array($timestampAuthority['validFor'])
                    || ! array_key_exists('start', $timestampAuthority['validFor'])
                    || ! is_string($timestampAuthority['validFor']['start'])
                    || $timestampAuthority['validFor']['start'] === ''
                ) {
                    continue;
                }

                $certChainPem = '';
                $certChainDer = [];
                /** @var mixed $certificateWrapper */
                foreach ($timestampAuthority['certChain']['certificates'] as $certificateWrapper) {
                    if (
                        ! is_array($certificateWrapper)
                        || ! array_key_exists('rawBytes', $certificateWrapper)
                        || ! is_string($certificateWrapper['rawBytes'])
                        || $certificateWrapper['rawBytes'] === ''
                    ) {
                        continue;
                    }

                    $certificate    = PemCertificate::fromBase64EncodedDerBytes($certificateWrapper['rawBytes']);
                    $certChainPem  .= $certificate->decoratedCertificate();
                    $certChainDer[] = $certificate->derEncodedBytes();
                }

                if ($certChainPem === '' || $certChainDer === []) {
                    continue;
                }

                $validForStart = strtotime($timestampAuthority['validFor']['start']);
                Assert::notFalse($validForStart);

                $validForEnd = null;
                if (
                    array_key_exists('end', $timestampAuthority['validFor'])
                    && $timestampAuthority['validFor']['end'] !== null
                ) {
                    Assert::stringNotEmpty($timestampAuthority['validFor']['end']);
                    $validForEnd = strtotime($timestampAuthority['validFor']['end']);
                    Assert::notFalse($validForEnd);
                }

                $candidates[] = [
                    'certChainPem' => $certChainPem,
                    'certChainDer' => $certChainDer,
                    'validFor' => [
                        'start' => $validForStart,
                        'end' => $validForEnd,
                    ],
                ];
            }
        }

        return $candidates;
    }

    public function isCertificateTransparencyLogIdTrusted(string $logId): bool
    {
        foreach ($this->parseDocuments() as $decoded) {
            if (
                ! is_array($decoded)
                || ! array_key_exists('ctlogs', $decoded)
                || ! is_array($decoded['ctlogs'])
            ) {
                continue;
            }

            /** @var mixed $ctlog */
            foreach ($decoded['ctlogs'] as $ctlog) {
                if (
                    ! is_array($ctlog)
                    || ! array_key_exists('logId', $ctlog)
                    || ! is_array($ctlog['logId'])
                    || ! array_key_exists('keyId', $ctlog['logId'])
                    || ! is_string($ctlog['logId']['keyId'])
                    || $ctlog['logId']['keyId'] === ''
                ) {
                    continue;
                }

                $ctlogKeyId = base64_decode($ctlog['logId']['keyId']);
                if ($ctlogKeyId !== '' && hash_equals($logId, $ctlogKeyId)) {
                    return true;
                }
            }
        }

        return false;
    }

    /** @param string|array<array-key, string> $issuerSubject */
    public function resolveCertificateAuthorityCertificate(string|array $issuerSubject): PemCertificate|null
    {
        foreach ($this->parseDocuments() as $decoded) {
            if (
                ! is_array($decoded)
                || ! array_key_exists('certificateAuthorities', $decoded)
                || ! is_array($decoded['certificateAuthorities'])
            ) {
                continue;
            }

            /** @var mixed $certificateAuthority */
            foreach ($decoded['certificateAuthorities'] as $certificateAuthority) {
                if (
                    ! is_array($certificateAuthority)
                    || ! array_key_exists('certChain', $certificateAuthority)
                    || ! is_array($certificateAuthority['certChain'])
                    || ! array_key_exists('certificates', $certificateAuthority['certChain'])
                    || ! is_array($certificateAuthority['certChain']['certificates'])
                ) {
                    continue;
                }

                /** @var mixed $caCertificateWrapper */
                foreach ($certificateAuthority['certChain']['certificates'] as $caCertificateWrapper) {
                    if (
                        ! is_array($caCertificateWrapper)
                        || ! array_key_exists('rawBytes', $caCertificateWrapper)
                        || ! is_string($caCertificateWrapper['rawBytes'])
                        || $caCertificateWrapper['rawBytes'] === ''
                    ) {
                        continue;
                    }

                    $caCertificate = PemCertificate::fromBase64EncodedDerBytes($caCertificateWrapper['rawBytes']);

                    $caCertificateInfo = openssl_x509_parse($caCertificate->decoratedCertificate());
                    Assert::isArray($caCertificateInfo);
                    Assert::keyExists($caCertificateInfo, 'subject');

                    if ($caCertificateInfo['subject'] !== $issuerSubject) {
                        continue;
                    }

                    return $caCertificate;
                }
            }
        }

        return null;
    }

    /** @return list<mixed> */
    private function parseDocuments(): array
    {
        $trustedRootCert = file_get_contents($this->trustedRootFilePath);
        Assert::stringNotEmpty($trustedRootCert);

        /** @var mixed $wholeFileDecoded */
        $wholeFileDecoded = json_decode(trim($trustedRootCert), true);
        if (is_array($wholeFileDecoded)) {
            return [$wholeFileDecoded];
        }

        $documents = [];
        foreach (explode("\n", trim($trustedRootCert)) as $jsonLine) {
            $documents[] = json_decode($jsonLine, true);
        }

        return $documents;
    }
}
