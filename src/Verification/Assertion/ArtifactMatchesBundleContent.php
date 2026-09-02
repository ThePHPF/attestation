<?php

declare(strict_types=1);

namespace ThePhpFoundation\Attestation\Verification\Assertion;

use OpenSSLAsymmetricKey;
use ThePhpFoundation\Attestation\Bundle;
use ThePhpFoundation\Attestation\DsseEnvelope;
use ThePhpFoundation\Attestation\FilenameWithChecksum;
use ThePhpFoundation\Attestation\MessageSignature;
use ThePhpFoundation\Attestation\PemCertificate;
use ThePhpFoundation\Attestation\Verification\Exception\CannotVerifyMessageSignatureWithoutArtifact;
use ThePhpFoundation\Attestation\Verification\Exception\DigestMismatch;
use ThePhpFoundation\Attestation\Verification\Exception\InvalidSubjectDefinition;
use ThePhpFoundation\Attestation\Verification\Exception\NoBcmath;
use ThePhpFoundation\Attestation\Verification\Exception\NoOpenSsl;
use ThePhpFoundation\Attestation\Verification\Exception\SignatureVerificationFailed;
use ThePhpFoundation\Attestation\Verification\Exception\UnsupportedBundleContent;
use ThePhpFoundation\Attestation\Verification\RawEcdsaDigestVerifier;
use Webmozart\Assert\Assert;

use function array_key_exists;
use function count;
use function extension_loaded;
use function file_get_contents;
use function hash_equals;
use function hex2bin;
use function is_array;
use function is_readable;
use function is_string;
use function json_decode;
use function openssl_pkey_get_details;
use function openssl_pkey_get_public;
use function openssl_verify;

use const OPENSSL_ALGO_SHA256;

/** @internal This is not a public API, so should not be depended upon unless you accept the risk of BC breaks */
final class ArtifactMatchesBundleContent implements VerifyBundleCheck
{
    public function assert(FilenameWithChecksum $file, int $bundleIndex, Bundle $bundle): void
    {
        if ($bundle->content() instanceof DsseEnvelope) {
            $this->assertDigestFromAttestationMatchesActual($file, $bundle->content());
            $this->verifyDsseEnvelopeSignature($bundleIndex, $bundle->certificate(), $bundle->content());
        } elseif ($bundle->content() instanceof MessageSignature) {
            $this->assertDigestFromMessageSignatureMatchesActual($file, $bundle->content());
            $this->verifyMessageSignature($bundleIndex, $file, $bundle->certificate(), $bundle->content());
        } else {
            throw UnsupportedBundleContent::new();
        }
    }

    private function verifyDsseEnvelopeSignature(int $bundleIndex, PemCertificate $certificate, DsseEnvelope $envelope): void
    {
        if (! extension_loaded('openssl')) {
            throw NoOpenssl::new();
        }

        $publicKey = openssl_pkey_get_public($certificate->decoratedCertificate());
        Assert::notFalse($publicKey);

        if (
            openssl_verify(
                $envelope->preAuthenticationEncoding(),
                $envelope->signature(),
                $publicKey,
                OPENSSL_ALGO_SHA256,
            ) !== 1
        ) {
            throw SignatureVerificationFailed::forIndex($bundleIndex);
        }
    }

    private function verifyMessageSignature(int $bundleIndex, FilenameWithChecksum $file, PemCertificate $certificate, MessageSignature $content): void
    {
        if (! extension_loaded('openssl')) {
            throw NoOpenssl::new();
        }

        $publicKey = openssl_pkey_get_public($certificate->decoratedCertificate());
        Assert::notFalse($publicKey);

        if (! is_readable($file->filename())) {
            $this->verifyMessageSignatureAgainstDigestAlone($bundleIndex, $file, $publicKey, $content);

            return;
        }

        $artifactContents = file_get_contents($file->filename());
        Assert::stringNotEmpty($artifactContents);

        if (
            openssl_verify(
                $artifactContents,
                $content->signature(),
                $publicKey,
                OPENSSL_ALGO_SHA256,
            ) !== 1
        ) {
            throw SignatureVerificationFailed::forIndex($bundleIndex);
        }
    }

    /**
     * ext-openssl's openssl_verify() always hashes the message it's given internally, so it can't verify a
     * signature against an already-computed digest when the real artifact isn't available (DIGEST mode).
     * Falls back to raw ECDSA point arithmetic via ext-bcmath, which is optional (see composer.json).
     */
    private function verifyMessageSignatureAgainstDigestAlone(int $bundleIndex, FilenameWithChecksum $file, OpenSSLAsymmetricKey $publicKey, MessageSignature $content): void
    {
        if (! extension_loaded('bcmath')) {
            throw NoBcmath::new();
        }

        $details = openssl_pkey_get_details($publicKey);
        Assert::isArray($details);

        if (
            ! array_key_exists('ec', $details)
            || ! is_array($details['ec'])
            || ! array_key_exists('curve_name', $details['ec'])
            || ! is_string($details['ec']['curve_name'])
            || ! RawEcdsaDigestVerifier::isCurveSupported($details['ec']['curve_name'])
        ) {
            throw CannotVerifyMessageSignatureWithoutArtifact::new();
        }

        Assert::stringNotEmpty($details['ec']['curve_name']);
        Assert::keyExists($details['ec'], 'x');
        Assert::stringNotEmpty($details['ec']['x']);
        Assert::keyExists($details['ec'], 'y');
        Assert::stringNotEmpty($details['ec']['y']);

        $digest = hex2bin($file->checksum());
        Assert::notFalse($digest);
        Assert::stringNotEmpty($digest);

        if (! RawEcdsaDigestVerifier::verify($details['ec']['curve_name'], $digest, $content->signature(), $details['ec']['x'], $details['ec']['y'])) {
            throw SignatureVerificationFailed::forIndex($bundleIndex);
        }
    }

    private function assertDigestFromMessageSignatureMatchesActual(FilenameWithChecksum $file, MessageSignature $content): void
    {
        $expected = $file->checksum();
        $actual   = $content->digestHex();
        if (! hash_equals($expected, $actual)) {
            throw DigestMismatch::fromChecksumMismatch($expected, $actual);
        }
    }

    private function assertDigestFromAttestationMatchesActual(FilenameWithChecksum $file, DsseEnvelope $envelope): void
    {
        /** @var mixed $decodedPayload */
        $decodedPayload = json_decode($envelope->payload(), true);

        if (
            ! is_array($decodedPayload)
            || ! array_key_exists('subject', $decodedPayload)
            || ! is_array($decodedPayload['subject'])
            || count($decodedPayload['subject']) !== 1
            || ! array_key_exists(0, $decodedPayload['subject'])
            || ! is_array($decodedPayload['subject'][0])
            || ! array_key_exists('name', $decodedPayload['subject'][0])
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
}
