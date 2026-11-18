<?php

declare(strict_types=1);

namespace ThePhpFoundation\Attestation\BundleSource;

use Composer\Downloader\TransportException;
use ThePhpFoundation\Attestation\Bundle;
use ThePhpFoundation\Attestation\BundleSource\Exception\MissingAttestation;
use ThePhpFoundation\Attestation\FilenameWithChecksum;

use function array_map;
use function sprintf;

class DownloadGitHubProvenance implements BundleSource
{
    /** @param non-empty-string $owner */
    public function __construct(private string $owner, private GitHubApi $gitHubApi)
    {
    }

    /** @param non-empty-string $owner */
    public static function factory(string $owner): self
    {
        return new self($owner, GitHubApi::factory());
    }

    /** @inheritDoc */
    public function getBundles(FilenameWithChecksum $file): array
    {
        try {
            $attestations = $this->gitHubApi->attestations(sprintf(
                '/orgs/%s/attestations/sha256:%s?predicate_type=provenance',
                $this->owner,
                $file->checksum(),
            ));

            if ($attestations === []) {
                throw MissingAttestation::from($file);
            }

            return array_map(
                /** @param array{initiator: string|null, bundle: array<array-key, mixed>} $attestation */
                static fn (array $attestation): Bundle => Bundle::fromBundle($attestation['bundle']),
                $attestations,
            );
        } catch (TransportException $transportException) {
            if ($transportException->getStatusCode() === 404) {
                throw MissingAttestation::from($file);
            }

            throw $transportException;
        }
    }
}
