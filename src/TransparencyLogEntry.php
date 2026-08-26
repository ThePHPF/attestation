<?php

declare(strict_types=1);

namespace ThePhpFoundation\Attestation;

use Webmozart\Assert\Assert;

use function array_key_exists;

/** @internal This is not a public API, so should not be depended upon unless you accept the risk of BC breaks */
final class TransparencyLogEntry
{
    public int $logIndex;
    /**
     * Absent for some entries (e.g. ones relying on `timestampVerificationData` instead), so this
     * can't be relied upon as always present.
     */
    public ?int $integratedTime;

    private function __construct(int $logIndex, ?int $integratedTime)
    {
        $this->logIndex       = $logIndex;
        $this->integratedTime = $integratedTime;
    }

    /** @param array<array-key, mixed> $transparencyLogEntry */
    public static function fromBundleTransparencyLogEntry(array $transparencyLogEntry): self
    {
        Assert::keyExists($transparencyLogEntry, 'logIndex');
        Assert::stringNotEmpty($transparencyLogEntry['logIndex']);
        Assert::numeric($transparencyLogEntry['logIndex']);

        $integratedTime = null;
        if (array_key_exists('integratedTime', $transparencyLogEntry)) {
            Assert::stringNotEmpty($transparencyLogEntry['integratedTime']);
            Assert::numeric($transparencyLogEntry['integratedTime']);
            $integratedTime = (int) $transparencyLogEntry['integratedTime'];
        }

        return new self(
            (int) $transparencyLogEntry['logIndex'],
            $integratedTime,
        );
    }
}
