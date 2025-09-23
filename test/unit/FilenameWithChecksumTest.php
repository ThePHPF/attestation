<?php

declare(strict_types=1);

namespace ThePhpFoundation\UnitTest\Attestation;

use PHPUnit\Framework\TestCase;
use ThePhpFoundation\Attestation\FilenameWithChecksum;

/** @covers \ThePhpFoundation\Attestation\FilenameWithChecksum */
final class FilenameWithChecksumTest extends TestCase
{
    public function testFromFilenameAndChecksum(): void
    {
        $filename = FilenameWithChecksum::fromFilenameAndChecksum('foo.bar', 'baz');
        self::assertSame('foo.bar', $filename->filename());
        self::assertSame('baz', $filename->checksum());
    }
}
