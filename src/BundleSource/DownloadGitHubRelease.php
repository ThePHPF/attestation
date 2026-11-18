<?php

declare(strict_types=1);

namespace ThePhpFoundation\Attestation\BundleSource;

use Composer\Downloader\TransportException;
use ThePhpFoundation\Attestation\Bundle;
use ThePhpFoundation\Attestation\BundleSource\Exception\MissingAttestation;
use ThePhpFoundation\Attestation\DsseEnvelope;
use ThePhpFoundation\Attestation\FilenameWithChecksum;
use ThePhpFoundation\Attestation\GitHubReleaseTag;

use function array_filter;
use function array_key_exists;
use function array_map;
use function array_values;
use function is_array;
use function json_decode;
use function rawurlencode;
use function sprintf;
use function strlen;

class DownloadGitHubRelease implements BundleSource
{
    private const GITHUB_INITIATOR = 'github';

    /**
     * @param non-empty-string $owner
     * @param non-empty-string $repo
     */
    public function __construct(private string $owner, private string $repo, private GitHubReleaseTag $tag, private GitHubApi $gitHubApi)
    {
    }

    /**
     * @param non-empty-string $owner
     * @param non-empty-string $repo
     */
    public static function factory(string $owner, string $repo, GitHubReleaseTag $tag): self
    {
        return new self($owner, $repo, $tag, GitHubApi::factory());
    }

    /** @inheritDoc */
    public function getBundles(FilenameWithChecksum $file): array
    {
        try {
            $attestations = $this->gitHubApi->attestations(sprintf(
                '/repos/%s/%s/attestations/%s:%s?predicate_type=release',
                rawurlencode($this->owner),
                rawurlencode($this->repo),
                strlen($this->tag->sha()) === 64 ? 'sha256' : 'sha1',
                $this->tag->sha(),
            ));
        } catch (TransportException $transportException) {
            if ($transportException->getStatusCode() === 404) {
                throw MissingAttestation::from($file);
            }

            throw $transportException;
        }

        $bundles = array_values(array_filter(
            array_map(
                /** @param array{initiator: string|null, bundle: array<array-key, mixed>} $attestation */
                static fn (array $attestation): Bundle|null => $attestation['initiator'] === self::GITHUB_INITIATOR
                    ? Bundle::fromBundle($attestation['bundle'])
                    : null,
                $attestations,
            ),
            fn (Bundle|null $bundle): bool => $bundle !== null && $this->isForTagAndFile($bundle, $file),
        ));

        if ($bundles === []) {
            throw MissingAttestation::from($file);
        }

        return $bundles;
    }

    private function isForTagAndFile(Bundle $bundle, FilenameWithChecksum $file): bool
    {
        $content = $bundle->content();
        if (! $content instanceof DsseEnvelope) {
            return false;
        }

        /** @var mixed $statement */
        $statement = json_decode($content->payload(), true);

        if (
            ! is_array($statement)
            || ! array_key_exists('predicate', $statement)
            || ! is_array($statement['predicate'])
            || ($statement['predicate']['tag'] ?? null) !== $this->tag->tagName()
            || ! array_key_exists('subject', $statement)
            || ! is_array($statement['subject'])
        ) {
            return false;
        }

        foreach ($statement['subject'] as $subject) {
            if (is_array($subject) && is_array($subject['digest'] ?? null) && ($subject['digest']['sha256'] ?? null) === $file->checksum()) {
                return true;
            }
        }

        return false;
    }
}
