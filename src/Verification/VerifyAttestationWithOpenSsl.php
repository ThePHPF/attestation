<?php

declare(strict_types=1);

namespace ThePhpFoundation\Attestation\Verification;

use Composer\Downloader\TransportException;
use Composer\Factory;
use Composer\IO\NullIO;
use Composer\Util\AuthHelper;
use Composer\Util\HttpDownloader;
use ThePhpFoundation\Attestation\Attestation;
use ThePhpFoundation\Attestation\FilenameWithChecksum;
use ThePhpFoundation\Attestation\Verification\Exception\DigestMismatch;
use ThePhpFoundation\Attestation\Verification\Exception\InvalidDerEncodedStringLength;
use ThePhpFoundation\Attestation\Verification\Exception\InvalidSubjectDefinition;
use ThePhpFoundation\Attestation\Verification\Exception\IssuerCertificateVerificationFailed;
use ThePhpFoundation\Attestation\Verification\Exception\MismatchingExtensionValues;
use ThePhpFoundation\Attestation\Verification\Exception\MissingAttestation;
use ThePhpFoundation\Attestation\Verification\Exception\NoIssuerCertificateInTrustedRoot;
use ThePhpFoundation\Attestation\Verification\Exception\NoOpenSsl;
use ThePhpFoundation\Attestation\Verification\Exception\SignatureVerificationFailed;
use Webmozart\Assert\Assert;

use function array_key_exists;
use function array_map;
use function count;
use function explode;
use function extension_loaded;
use function file_get_contents;
use function hash_equals;
use function is_array;
use function is_string;
use function json_decode;
use function openssl_pkey_get_public;
use function openssl_verify;
use function openssl_x509_parse;
use function openssl_x509_verify;
use function ord;
use function sprintf;
use function strlen;
use function substr;
use function trim;
use function wordwrap;

use const OPENSSL_ALGO_SHA256;

class VerifyAttestationWithOpenSsl implements VerifyAttestation
{
    public const TRUSTED_ROOT_FILE_PATH = __DIR__ . '/../../resources/trusted-root.jsonl';

    private const GITHUB_API_URL = 'https://api.github.com';

    /** @var non-empty-string */
    private string $trustedRootFilePath;
    /** @var non-empty-string */
    private string $githubApiBaseUrl;
    private HttpDownloader $httpDownloader;
    private AuthHelper $authHelper;

    /**
     * @param non-empty-string $trustedRootFilePath
     * @param non-empty-string $githubApiBaseUrl
     */
    public function __construct(
        string $trustedRootFilePath,
        string $githubApiBaseUrl,
        HttpDownloader $httpDownloader,
        AuthHelper $authHelper
    ) {
        $this->authHelper          = $authHelper;
        $this->httpDownloader      = $httpDownloader;
        $this->githubApiBaseUrl    = $githubApiBaseUrl;
        $this->trustedRootFilePath = $trustedRootFilePath;
    }

    public static function factory(): self
    {
        $io     = new NullIO();
        $config = Factory::createConfig();
        $io->loadConfiguration($config);
        $http = Factory::createHttpDownloader($io, $config);

        return new self(
            self::TRUSTED_ROOT_FILE_PATH,
            self::GITHUB_API_URL,
            $http,
            new AuthHelper($io, $config),
        );
    }

    /** @inheritDoc */
    public function verify(
        FilenameWithChecksum $file,
        string $owner,
        string $expectedSubjectName,
        array $extensionsToVerify
    ): void {
        $attestations = $this->downloadAttestations($file, $owner);

        foreach ($attestations as $attestationIndex => $attestation) {
            /**
             * Useful references. Whilst we don't do the full verification that
             * `gh attestation verify` would (since we don't want to re-invent
             * the wheel), we can do some basic check of the DSSE Envelope.
             * We'll check the payload digest matches our expectation, and
             * verify the signature with the certificate.
             *
             *  - https://github.com/cli/cli/blob/234d2effd545fb9d72ea77aa648caa499aecaa6e/pkg/cmd/attestation/verify/verify.go#L225-L256
             *  - https://docs.sigstore.dev/logging/verify-release/
             *  - https://github.com/secure-systems-lab/dsse/blob/master/protocol.md#protocol
             */
            $this->assertCertificateSignedByTrustedRoot($attestation);

            $this->assertCertificateExtensionClaims($attestation, $extensionsToVerify);

            $this->assertDigestFromAttestationMatchesActual($file, $expectedSubjectName, $attestation);

            $this->verifyDsseEnvelopeSignature($attestationIndex, $attestation);
        }
    }

    private function assertCertificateSignedByTrustedRoot(Attestation $attestation): void
    {
        $attestationCertificateInfo = openssl_x509_parse($attestation->certificate);
        Assert::isArray($attestationCertificateInfo);
        Assert::keyExists($attestationCertificateInfo, 'issuer');
        if (is_array($attestationCertificateInfo['issuer'])) {
            Assert::allStringNotEmpty($attestationCertificateInfo['issuer']);
        } else {
            Assert::stringNotEmpty($attestationCertificateInfo['issuer']);
        }

        $trustedRootCert = file_get_contents($this->trustedRootFilePath);
        Assert::stringNotEmpty($trustedRootCert);
        $trustedRootJsonLines = explode("\n", trim($trustedRootCert));

        /**
         * Now go through our trusted root certificates and attempt to verify that the certificate was signed by an
         * in-date trusted root certificate. The root certificates should be periodically and frequently updated using:
         *
         *     gh attestation trusted-root > resources/trusted-root.jsonl
         *
         * And verifying the contents afterwards to ensure they have not been compromised. This list of JSON blobs may
         * have multiple certificates (e.g. root certificates, intermediate certificates, expired certificates, etc.)
         * so we should loop over to find the correct certificate used to sign the attestation certificate.
         */
        foreach ($trustedRootJsonLines as $jsonLine) {
            /** @var mixed $decoded */
            $decoded = json_decode($jsonLine, true);

            // No certificate authorities defined in this JSON line, skip it...
            if (
                ! is_array($decoded)
                || ! array_key_exists('certificateAuthorities', $decoded)
                || ! is_array($decoded['certificateAuthorities'])
            ) {
                continue;
            }

            /** @var mixed $certificateAuthority */
            foreach ($decoded['certificateAuthorities'] as $certificateAuthority) {
                // We don't have a certificate chain defined, skip it...
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
                    // Certificate is not in the expected format, i.e. no rawBytes key, skip it...
                    if (
                        ! is_array($caCertificateWrapper)
                        || ! array_key_exists('rawBytes', $caCertificateWrapper)
                        || ! is_string($caCertificateWrapper['rawBytes'])
                        || $caCertificateWrapper['rawBytes'] === ''
                    ) {
                        continue;
                    }

                    // Embed the base64-encoded DER into a PEM envelope for consumption by OpenSSL.
                    $caCertificateString = sprintf(
                        <<<'EOT'
                        -----BEGIN CERTIFICATE-----
                        %s
                        -----END CERTIFICATE-----
                        EOT,
                        wordwrap($caCertificateWrapper['rawBytes'], 67, "\n", true),
                    );

                    $caCertificateInfo = openssl_x509_parse($caCertificateString);
                    Assert::isArray($caCertificateInfo);
                    Assert::keyExists($caCertificateInfo, 'subject');

                    // If the CA certificate subject is not the issuer of the attestation certificate,
                    // this was not the cert we were looking for, skip it...
                    if ($caCertificateInfo['subject'] !== $attestationCertificateInfo['issuer']) {
                        continue;
                    }

                    // Finally, verify that the located CA cert was used to sign the attestation certificate
                    if (openssl_x509_verify($attestation->certificate, $caCertificateString) !== 1) {
                        /** @psalm-suppress MixedArgument */
                        throw IssuerCertificateVerificationFailed::fromIssuer($attestationCertificateInfo['issuer']);
                    }

                    return;
                }
            }
        }

        /**
         * If we got here, we skipped all the certificates in the trusted root collection for various reasons; so we
         * therefore cannot trust the attestation certificate.
         *
         * @psalm-suppress MixedArgument
         */
        throw NoIssuerCertificateInTrustedRoot::fromIssuer($attestationCertificateInfo['issuer']);
    }

    /** @param array<non-empty-string, string> $extensions */
    private function assertCertificateExtensionClaims(Attestation $attestation, array $extensions): void
    {
        $attestationCertificateInfo = openssl_x509_parse($attestation->certificate);
        Assert::isArray($attestationCertificateInfo);
        Assert::keyExists($attestationCertificateInfo, 'extensions');
        Assert::isArray($attestationCertificateInfo['extensions']);

        /**
         * See {@link https://github.com/sigstore/fulcio/blob/main/docs/oid-info.md#136141572641--fulcio} for details
         * on the Fulcio extension keys; note the values are DER-encoded strings; the ASN.1 tag is UTF8String (0x0C).
         *
         * Check the extension values are what we expect; these are hard-coded, as we don't expect them
         * to change unless the namespace/repo name change, etc.
         */
        foreach ($extensions as $extension => $expectedValue) {
            Assert::keyExists($attestationCertificateInfo['extensions'], $extension);
            Assert::stringNotEmpty($attestationCertificateInfo['extensions'][$extension]);
            $actualValue = $attestationCertificateInfo['extensions'][$extension];

            // First character (the ASN.1 tag) is expected to be UTF8String (0x0C)
            if (ord($actualValue[0]) !== 0x0C) {
                throw MismatchingExtensionValues::from($extension, $expectedValue, $actualValue);
            }

            /**
             * Second character is expected to be the length of the actual value
             * as long as they are less than 127 bytes (short form)
             *
             * @link https://www.oss.com/asn1/resources/asn1-made-simple/asn1-quick-reference/basic-encoding-rules.html#Lengths
             */
            $expectedValueLength = ord($actualValue[1]);
            if (strlen($actualValue) !== 2 + $expectedValueLength) {
                throw InvalidDerEncodedStringLength::fromDerString($actualValue, 2 + $expectedValueLength);
            }

            $derDecodedValue = substr($actualValue, 2, $expectedValueLength);
            if ($derDecodedValue !== $expectedValue) {
                throw MismatchingExtensionValues::from($extension, $expectedValue, $derDecodedValue);
            }
        }
    }

    private function verifyDsseEnvelopeSignature(int $attestationIndex, Attestation $attestation): void
    {
        if (! extension_loaded('openssl')) {
            throw NoOpenssl::new();
        }

        $publicKey = openssl_pkey_get_public($attestation->certificate);
        Assert::notFalse($publicKey);

        $preAuthenticationEncoding = sprintf(
            'DSSEv1 %d %s %d %s',
            strlen($attestation->dsseEnvelopePayloadType),
            $attestation->dsseEnvelopePayloadType,
            strlen($attestation->dsseEnvelopePayload),
            $attestation->dsseEnvelopePayload,
        );

        if (openssl_verify($preAuthenticationEncoding, $attestation->dsseEnvelopeSignature, $publicKey, OPENSSL_ALGO_SHA256) !== 1) {
            throw SignatureVerificationFailed::forIndex($attestationIndex);
        }
    }

    /** @param non-empty-string $expectedSubjectName */
    private function assertDigestFromAttestationMatchesActual(FilenameWithChecksum $file, string $expectedSubjectName, Attestation $attestation): void
    {
        /** @var mixed $decodedPayload */
        $decodedPayload = json_decode($attestation->dsseEnvelopePayload, true);

        if (
            ! is_array($decodedPayload)
            || ! array_key_exists('subject', $decodedPayload)
            || ! is_array($decodedPayload['subject'])
            || count($decodedPayload['subject']) !== 1
            || ! array_key_exists(0, $decodedPayload['subject'])
            || ! is_array($decodedPayload['subject'][0])
            || ! array_key_exists('name', $decodedPayload['subject'][0])
            || $decodedPayload['subject'][0]['name'] !== $expectedSubjectName
            || ! array_key_exists('digest', $decodedPayload['subject'][0])
            || ! is_array($decodedPayload['subject'][0]['digest'])
            || ! array_key_exists('sha256', $decodedPayload['subject'][0]['digest'])
            || ! is_string($decodedPayload['subject'][0]['digest']['sha256'])
            || $decodedPayload['subject'][0]['digest']['sha256'] === ''
        ) {
            throw InvalidSubjectDefinition::new();
        }

        $expected = $file->checksum();
        $actual   = $decodedPayload['subject'][0]['digest']['sha256'];
        if (! hash_equals($expected, $actual)) {
            throw DigestMismatch::fromChecksumMismatch($expected, $actual);
        }
    }

    /**
     * @param non-empty-string $owner
     *
     * @return non-empty-list<Attestation>
     */
    private function downloadAttestations(FilenameWithChecksum $file, string $owner): array
    {
        $attestationUrl = sprintf(
            '%s/orgs/%s/attestations/sha256:%s',
            $this->githubApiBaseUrl,
            $owner,
            $file->checksum(),
        );

        try {
            $decodedJson = $this->httpDownloader->get(
                $attestationUrl,
                [
                    'retry-auth-failure' => true,
                    'http' => [
                        'method' => 'GET',
                        'header' => $this->authHelper->addAuthenticationHeader([], $this->githubApiBaseUrl, $attestationUrl),
                    ],
                ],
            )->decodeJson();

            Assert::isArray($decodedJson);
            Assert::keyExists($decodedJson, 'attestations');
            Assert::isNonEmptyList($decodedJson['attestations']);

            return array_map(
                /** @param mixed $attestation */
                static function ($attestation): Attestation {
                    Assert::isArray($attestation);

                    return Attestation::fromAttestationBundleWithDsseEnvelope($attestation);
                },
                $decodedJson['attestations'],
            );
        } catch (TransportException $transportException) {
            if ($transportException->getStatusCode() === 404) {
                throw MissingAttestation::from($file);
            }

            throw $transportException;
        }
    }
}
