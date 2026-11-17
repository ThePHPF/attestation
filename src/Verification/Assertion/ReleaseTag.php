<?php

declare(strict_types=1);

namespace ThePhpFoundation\Attestation\Verification\Assertion;

use ThePhpFoundation\Attestation\Bundle;
use ThePhpFoundation\Attestation\DsseEnvelope;
use ThePhpFoundation\Attestation\FilenameWithChecksum;
use ThePhpFoundation\Attestation\Verification\Exception\ReleaseTagMismatch;

use function array_key_exists;
use function is_array;
use function is_string;
use function json_decode;

/** @internal This is not a public API, so should not be depended upon unless you accept the risk of BC breaks */
final class ReleaseTag implements VerifyBundleCheck
{
    /** @param non-empty-string $expectedTag */
    public function __construct(private string $expectedTag)
    {
    }

    public function assert(FilenameWithChecksum $file, int $bundleIndex, Bundle $bundle): void
    {
        $content = $bundle->content();
        if (! $content instanceof DsseEnvelope) {
            throw ReleaseTagMismatch::from($this->expectedTag, '(missing)');
        }

        /** @var mixed $statement */
        $statement = json_decode($content->payload(), true);

        if (
            ! is_array($statement)
            || ! array_key_exists('predicate', $statement)
            || ! is_array($statement['predicate'])
            || ! array_key_exists('tag', $statement['predicate'])
            || ! is_string($statement['predicate']['tag'])
        ) {
            throw ReleaseTagMismatch::from($this->expectedTag, '(missing)');
        }

        if ($statement['predicate']['tag'] !== $this->expectedTag) {
            throw ReleaseTagMismatch::from($this->expectedTag, $statement['predicate']['tag']);
        }
    }
}
