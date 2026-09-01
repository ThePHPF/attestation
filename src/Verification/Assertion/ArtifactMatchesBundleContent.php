<?php

declare(strict_types=1);

namespace ThePhpFoundation\Attestation\Verification\Assertion;

use ThePhpFoundation\Attestation\Bundle;
use ThePhpFoundation\Attestation\DsseEnvelope;
use ThePhpFoundation\Attestation\FilenameWithChecksum;
use ThePhpFoundation\Attestation\MessageSignature;
use ThePhpFoundation\Attestation\PemCertificate;
use ThePhpFoundation\Attestation\Verification\Exception\CannotVerifyMessageSignatureWithoutArtifact;
use ThePhpFoundation\Attestation\Verification\Exception\DigestMismatch;
use ThePhpFoundation\Attestation\Verification\Exception\InvalidSubjectDefinition;
use ThePhpFoundation\Attestation\Verification\Exception\NoOpenSsl;
use ThePhpFoundation\Attestation\Verification\Exception\SignatureVerificationFailed;
use ThePhpFoundation\Attestation\Verification\Exception\UnsupportedBundleContent;
use Webmozart\Assert\Assert;

use function array_key_exists;
use function count;
use function extension_loaded;
use function file_get_contents;
use function hash_equals;
use function is_array;
use function is_readable;
use function is_string;
use function json_decode;
use function openssl_pkey_get_public;
use function openssl_verify;

use const OPENSSL_ALGO_SHA256;

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

    /**
     * This requires the artifact on disk to verify the signature. A digest-only verification is specifically not
     * supported, as there's nothing to verify against.
     */
    private function verifyMessageSignature(int $bundleIndex, FilenameWithChecksum $file, PemCertificate $certificate, MessageSignature $content): void
    {
        if (! extension_loaded('openssl')) {
            throw NoOpenssl::new();
        }

        if (! is_readable($file->filename())) {
            throw CannotVerifyMessageSignatureWithoutArtifact::new();
        }

        $artifactContents = file_get_contents($file->filename());
        Assert::stringNotEmpty($artifactContents);

        $publicKey = openssl_pkey_get_public($certificate->decoratedCertificate());
        Assert::notFalse($publicKey);

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
