<?php

declare(strict_types=1);

namespace ThePhpFoundation\Attestation;

use ThePhpFoundation\Attestation\Verification\Exception\UnsupportedTransparencyLogEntryKind;
use Webmozart\Assert\Assert;

use function array_key_exists;
use function base64_decode;

/** @internal This is not a public API, so should not be depended upon unless you accept the risk of BC breaks */
final class TransparencyLogEntry
{
    private int $logIndex;
    private ?int $integratedTime;
    /** @var 'hashedrekord'|'dsse'|'intoto' */
    private string $kind;
    /** @var non-empty-string */
    private string $version;
    /** @var non-empty-string */
    private string $logId;
    private string $canonicalizedBody;
    /** @var non-empty-string|null */
    private ?string $signedEntryTimestamp;
    private ?InclusionProof $inclusionProof;

    /**
     * @param 'hashedrekord'|'dsse'|'intoto' $kind
     * @param non-empty-string               $version
     * @param non-empty-string               $logId
     * @param non-empty-string|null          $signedEntryTimestamp
     */
    private function __construct(
        int $logIndex,
        ?int $integratedTime,
        string $kind,
        string $version,
        string $logId,
        string $canonicalizedBody,
        ?string $signedEntryTimestamp,
        ?InclusionProof $inclusionProof
    ) {
        $this->logIndex             = $logIndex;
        $this->integratedTime       = $integratedTime;
        $this->kind                 = $kind;
        $this->version              = $version;
        $this->logId                = $logId;
        $this->canonicalizedBody    = $canonicalizedBody;
        $this->signedEntryTimestamp = $signedEntryTimestamp;
        $this->inclusionProof       = $inclusionProof;
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

        Assert::keyExists($transparencyLogEntry, 'kindVersion');
        Assert::isArray($transparencyLogEntry['kindVersion']);
        Assert::keyExists($transparencyLogEntry['kindVersion'], 'kind');
        Assert::stringNotEmpty($transparencyLogEntry['kindVersion']['kind']);
        $kind = $transparencyLogEntry['kindVersion']['kind'];
        if ($kind !== 'hashedrekord' && $kind !== 'dsse' && $kind !== 'intoto') {
            throw UnsupportedTransparencyLogEntryKind::fromKind($kind);
        }

        Assert::keyExists($transparencyLogEntry['kindVersion'], 'version');
        Assert::stringNotEmpty($transparencyLogEntry['kindVersion']['version']);
        $version = $transparencyLogEntry['kindVersion']['version'];

        Assert::keyExists($transparencyLogEntry, 'logId');
        Assert::isArray($transparencyLogEntry['logId']);
        Assert::keyExists($transparencyLogEntry['logId'], 'keyId');
        Assert::stringNotEmpty($transparencyLogEntry['logId']['keyId']);
        $logId = base64_decode($transparencyLogEntry['logId']['keyId']);
        Assert::stringNotEmpty($logId);

        Assert::keyExists($transparencyLogEntry, 'canonicalizedBody');
        Assert::stringNotEmpty($transparencyLogEntry['canonicalizedBody']);
        $canonicalizedBody = base64_decode($transparencyLogEntry['canonicalizedBody']);
        Assert::stringNotEmpty($canonicalizedBody);

        $signedEntryTimestamp = null;
        if (array_key_exists('inclusionPromise', $transparencyLogEntry)) {
            Assert::isArray($transparencyLogEntry['inclusionPromise']);
            if (array_key_exists('signedEntryTimestamp', $transparencyLogEntry['inclusionPromise'])) {
                Assert::stringNotEmpty($transparencyLogEntry['inclusionPromise']['signedEntryTimestamp']);
                $signedEntryTimestamp = base64_decode($transparencyLogEntry['inclusionPromise']['signedEntryTimestamp']);
                Assert::stringNotEmpty($signedEntryTimestamp);
            }
        }

        $inclusionProof = null;
        if (array_key_exists('inclusionProof', $transparencyLogEntry)) {
            Assert::isArray($transparencyLogEntry['inclusionProof']);
            $inclusionProof = InclusionProof::fromBundleInclusionProof($transparencyLogEntry['inclusionProof']);
        }

        return new self(
            (int) $transparencyLogEntry['logIndex'],
            $integratedTime,
            $kind,
            $version,
            $logId,
            $canonicalizedBody,
            $signedEntryTimestamp,
            $inclusionProof,
        );
    }

    public function logIndex(): int
    {
        return $this->logIndex;
    }

    public function integratedTime(): ?int
    {
        return $this->integratedTime;
    }

    /** @return 'hashedrekord'|'dsse'|'intoto' */
    public function kind(): string
    {
        return $this->kind;
    }

    /** @return non-empty-string */
    public function version(): string
    {
        return $this->version;
    }

    /** @return non-empty-string */
    public function logId(): string
    {
        return $this->logId;
    }

    public function canonicalizedBody(): string
    {
        return $this->canonicalizedBody;
    }

    /** @return non-empty-string|null */
    public function signedEntryTimestamp(): ?string
    {
        return $this->signedEntryTimestamp;
    }

    public function inclusionProof(): ?InclusionProof
    {
        return $this->inclusionProof;
    }
}
