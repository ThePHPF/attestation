<?php

declare(strict_types=1);

namespace ThePhpFoundation\Attestation\BundleSource;

use Composer\Downloader\TransportException;
use ThePhpFoundation\Attestation\BundleSource\Exception\ReleaseTagNotFound;
use ThePhpFoundation\Attestation\GitHubReleaseTag;
use Webmozart\Assert\Assert;

use function rawurlencode;
use function sprintf;

class ResolveGitHubReleaseTag
{
    public function __construct(private GitHubApi $gitHubApi)
    {
    }

    public static function factory(): self
    {
        return new self(GitHubApi::factory());
    }

    /**
     * @param non-empty-string $owner
     * @param non-empty-string $repo
     * @param non-empty-string $tagName
     */
    public function resolve(string $owner, string $repo, string $tagName): GitHubReleaseTag
    {
        try {
            $decodedJson = $this->gitHubApi->getJson(sprintf(
                '/repos/%s/%s/git/ref/tags/%s',
                rawurlencode($owner),
                rawurlencode($repo),
                rawurlencode($tagName),
            ));
        } catch (TransportException $transportException) {
            if ($transportException->getStatusCode() === 404) {
                throw ReleaseTagNotFound::from($owner, $repo, $tagName);
            }

            throw $transportException;
        }

        Assert::isArray($decodedJson);
        Assert::keyExists($decodedJson, 'object');
        Assert::isArray($decodedJson['object']);
        Assert::keyExists($decodedJson['object'], 'sha');
        Assert::stringNotEmpty($decodedJson['object']['sha']);

        return GitHubReleaseTag::from($tagName, $decodedJson['object']['sha']);
    }
}
