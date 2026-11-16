<?php

declare(strict_types=1);

namespace ThePhpFoundation\Attestation\Verification\Assertion;

use ThePhpFoundation\Attestation\Bundle;
use ThePhpFoundation\Attestation\DsseEnvelope;
use ThePhpFoundation\Attestation\FilenameWithChecksum;
use ThePhpFoundation\Attestation\Verification\Exception\PredicateTypeMismatch;

use function array_key_exists;
use function is_array;
use function is_string;
use function json_decode;

/** @internal This is not a public API, so should not be depended upon unless you accept the risk of BC breaks */
final class PredicateType implements VerifyBundleCheck
{
    /** @param non-empty-string $expectedPredicateType */
    public function __construct(private string $expectedPredicateType)
    {
    }

    public function assert(FilenameWithChecksum $file, int $bundleIndex, Bundle $bundle): void
    {
        $content = $bundle->content();
        if (! $content instanceof DsseEnvelope) {
            return;
        }

        /** @var mixed $statement */
        $statement = json_decode($content->payload(), true);

        if (
            ! is_array($statement)
            || ! array_key_exists('predicateType', $statement)
            || ! is_string($statement['predicateType'])
        ) {
            throw PredicateTypeMismatch::from($this->expectedPredicateType, '(missing)');
        }

        if ($statement['predicateType'] !== $this->expectedPredicateType) {
            throw PredicateTypeMismatch::from($this->expectedPredicateType, $statement['predicateType']);
        }
    }
}
