<?php

declare(strict_types=1);

namespace ThePhpFoundation\Attestation\Verification\Assertion;

use ThePhpFoundation\Attestation\Bundle;
use ThePhpFoundation\Attestation\DsseEnvelope;
use ThePhpFoundation\Attestation\FilenameWithChecksum;
use ThePhpFoundation\Attestation\Verification\Exception\ReleaseTagDigestMismatch;

use function array_key_exists;
use function hash_equals;
use function is_array;
use function is_string;
use function json_decode;
use function strlen;

/** @internal This is not a public API, so should not be depended upon unless you accept the risk of BC breaks */
final class SubjectDigestMatchesReleaseTag implements VerifyBundleCheck
{
    /** @param non-empty-string $expectedTagDigest */
    public function __construct(private string $expectedTagDigest)
    {
    }

    public function assert(FilenameWithChecksum $file, int $bundleIndex, Bundle $bundle): void
    {
        $digestAlgorithm = strlen($this->expectedTagDigest) === 64 ? 'sha256' : 'sha1';

        $content = $bundle->content();
        if (! $content instanceof DsseEnvelope) {
            throw ReleaseTagDigestMismatch::from($digestAlgorithm, $this->expectedTagDigest);
        }

        /** @var mixed $statement */
        $statement = json_decode($content->payload(), true);

        if (! is_array($statement) || ! array_key_exists('subject', $statement) || ! is_array($statement['subject'])) {
            throw ReleaseTagDigestMismatch::from($digestAlgorithm, $this->expectedTagDigest);
        }

        foreach ($statement['subject'] as $subject) {
            if (
                is_array($subject)
                && array_key_exists('digest', $subject)
                && is_array($subject['digest'])
                && array_key_exists($digestAlgorithm, $subject['digest'])
                && is_string($subject['digest'][$digestAlgorithm])
                && hash_equals($this->expectedTagDigest, $subject['digest'][$digestAlgorithm])
            ) {
                return;
            }
        }

        throw ReleaseTagDigestMismatch::from($digestAlgorithm, $this->expectedTagDigest);
    }
}
