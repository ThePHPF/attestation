<?php

declare(strict_types=1);

namespace ThePhpFoundation\Attestation;

use Webmozart\Assert\Assert;

use function array_key_exists;
use function base64_decode;

/** @internal This is not a public API, so should not be depended upon unless you accept the risk of BC breaks */
final class InclusionProof
{
    private int $logIndex;
    private string $rootHash;
    private int $treeSize;
    /** @var list<string> */
    private array $hashes;
    private ?string $checkpointEnvelope;

    /** @param list<string> $hashes */
    private function __construct(int $logIndex, string $rootHash, int $treeSize, array $hashes, ?string $checkpointEnvelope)
    {
        $this->logIndex           = $logIndex;
        $this->rootHash           = $rootHash;
        $this->treeSize           = $treeSize;
        $this->hashes             = $hashes;
        $this->checkpointEnvelope = $checkpointEnvelope;
    }

    /** @param array<array-key, mixed> $inclusionProof */
    public static function fromBundleInclusionProof(array $inclusionProof): self
    {
        Assert::keyExists($inclusionProof, 'logIndex');
        Assert::stringNotEmpty($inclusionProof['logIndex']);
        Assert::numeric($inclusionProof['logIndex']);

        Assert::keyExists($inclusionProof, 'rootHash');
        Assert::stringNotEmpty($inclusionProof['rootHash']);
        $rootHash = base64_decode($inclusionProof['rootHash']);
        Assert::stringNotEmpty($rootHash);

        Assert::keyExists($inclusionProof, 'treeSize');
        Assert::stringNotEmpty($inclusionProof['treeSize']);
        Assert::numeric($inclusionProof['treeSize']);

        Assert::keyExists($inclusionProof, 'hashes');
        Assert::isArray($inclusionProof['hashes']);
        $hashes = [];
        foreach ($inclusionProof['hashes'] as $hash) {
            Assert::stringNotEmpty($hash);
            $decodedHash = base64_decode($hash);
            Assert::stringNotEmpty($decodedHash);
            $hashes[] = $decodedHash;
        }

        $checkpointEnvelope = null;
        if (array_key_exists('checkpoint', $inclusionProof)) {
            Assert::isArray($inclusionProof['checkpoint']);
            if (array_key_exists('envelope', $inclusionProof['checkpoint'])) {
                Assert::stringNotEmpty($inclusionProof['checkpoint']['envelope']);
                $checkpointEnvelope = $inclusionProof['checkpoint']['envelope'];
            }
        }

        return new self(
            (int) $inclusionProof['logIndex'],
            $rootHash,
            (int) $inclusionProof['treeSize'],
            $hashes,
            $checkpointEnvelope,
        );
    }

    public function logIndex(): int
    {
        return $this->logIndex;
    }

    public function rootHash(): string
    {
        return $this->rootHash;
    }

    public function treeSize(): int
    {
        return $this->treeSize;
    }

    /** @return list<string> */
    public function hashes(): array
    {
        return $this->hashes;
    }

    public function checkpointEnvelope(): ?string
    {
        return $this->checkpointEnvelope;
    }
}
