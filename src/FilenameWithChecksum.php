<?php

declare(strict_types=1);

namespace ThePhpFoundation\Attestation;

use Webmozart\Assert\Assert;

use function hash_file;

final class FilenameWithChecksum
{
    private const HASH_TYPE_SHA256 = 'sha256';

    /** @var non-empty-string */
    private string $filename;
    /** @var non-empty-string */
    private string $checksum;

    /**
     * @param non-empty-string $filename
     * @param non-empty-string $checksum
     */
    private function __construct(string $filename, string $checksum)
    {
        $this->filename = $filename;
        $this->checksum = $checksum;
    }

    /** @param non-empty-string $filename */
    public static function fromFilename(string $filename): self
    {
        $hash = hash_file(self::HASH_TYPE_SHA256, $filename);
        Assert::stringNotEmpty($hash);

        return new self($filename, $hash);
    }

    /** @return non-empty-string */
    public function checksum(): string
    {
        return $this->checksum;
    }

    /** @return non-empty-string */
    public function filename(): string
    {
        return $this->filename;
    }
}
