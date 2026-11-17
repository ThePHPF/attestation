<?php

declare(strict_types=1);

namespace ThePhpFoundation\Attestation;

use Webmozart\Assert\Assert;

/**
 * @internal This is not a public API, so should not be depended upon unless you accept the risk of BC breaks
 *
 * @immutable
 */
final class GitHubReleaseTag
{
    /**
     * @param non-empty-string $tagName
     * @param non-empty-string $sha
     */
    private function __construct(private string $tagName, private string $sha)
    {
    }

    /**
     * @param non-empty-string $tagName
     * @param non-empty-string $sha     the git object SHA the tag ref points to, as returned by GitHub's git refs API
     */
    public static function from(string $tagName, string $sha): self
    {
        Assert::regex($sha, '/^(?:[0-9a-f]{40}|[0-9a-f]{64})$/');

        return new self($tagName, $sha);
    }

    /** @return non-empty-string */
    public function tagName(): string
    {
        return $this->tagName;
    }

    /** @return non-empty-string */
    public function sha(): string
    {
        return $this->sha;
    }
}
