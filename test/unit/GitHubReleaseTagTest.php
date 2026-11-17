<?php

declare(strict_types=1);

namespace ThePhpFoundation\UnitTest\Attestation;

use InvalidArgumentException;
use PHPUnit\Framework\TestCase;
use ThePhpFoundation\Attestation\GitHubReleaseTag;

/** @covers \ThePhpFoundation\Attestation\GitHubReleaseTag */
final class GitHubReleaseTagTest extends TestCase
{
    public function testFromTagNameAndSha1(): void
    {
        $tag = GitHubReleaseTag::from('1.5.5', 'a41ca99acf93460f75a2acd830b2b8f013571e3a');

        self::assertSame('1.5.5', $tag->tagName());
        self::assertSame('a41ca99acf93460f75a2acd830b2b8f013571e3a', $tag->sha());
    }

    public function testFromTagNameAndSha256(): void
    {
        $tag = GitHubReleaseTag::from('1.5.5', '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08');

        self::assertSame('9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08', $tag->sha());
    }

    /** @return array<non-empty-string, array{non-empty-string}> */
    public function invalidShaProvider(): array
    {
        return [
            'too short' => ['a41ca99a'],
            'between sha1 and sha256 length' => ['a41ca99acf93460f75a2acd830b2b8f013571e3a0000'],
            'not hex' => ['z41ca99acf93460f75a2acd830b2b8f013571e3a'],
        ];
    }

    /**
     * @param non-empty-string $sha
     *
     * @dataProvider invalidShaProvider
     */
    public function testRejectsAShaThatIsNotASha1OrSha256HexDigest(string $sha): void
    {
        $this->expectException(InvalidArgumentException::class);
        GitHubReleaseTag::from('1.5.5', $sha);
    }
}
