<?php

declare(strict_types=1);

namespace ThePhpFoundation\Attestation;

use Webmozart\Assert\Assert;

/** @internal This is not a public API, so should not be depended upon unless you accept the risk of BC breaks */
final class TransparencyLogEntry
{
    public int $logIndex;

    private function __construct(int $logIndex)
    {
        $this->logIndex = $logIndex;
    }

    /** @param array<array-key, mixed> $transparencyLogEntry */
    public static function fromBundleTransparencyLogEntry(array $transparencyLogEntry): self
    {
        Assert::keyExists($transparencyLogEntry, 'logIndex');
        Assert::stringNotEmpty($transparencyLogEntry['logIndex']);
        Assert::numeric($transparencyLogEntry['logIndex']);

        return new self((int) $transparencyLogEntry['logIndex']);
    }
}
