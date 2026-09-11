<?php

declare(strict_types=1);

namespace ThePhpFoundation\UnitTest\Attestation\Verification;

use PHPUnit\Framework\TestCase;
use ThePhpFoundation\Attestation\Verification\Der;
use Webmozart\Assert\InvalidArgumentException;

use function base64_encode;
use function str_repeat;

/** @covers \ThePhpFoundation\Attestation\Verification\Der */
final class DerTest extends TestCase
{
    public function testBytesFromPemStripsTheHeaderFooterAndNewlinesAndDecodesTheBase64Content(): void
    {
        $der = Der::bytesFromPem(
            "-----BEGIN CERTIFICATE-----\n"
            . base64_encode('not a real certificate') . "\n"
            . "-----END CERTIFICATE-----\n",
        );

        self::assertSame('not a real certificate', $der);
    }

    public function testReadTlvReadsAShortFormLengthTlv(): void
    {
        [$tag, $value, $nextOffset] = Der::readTlv("\x04\x05hello", 0);

        self::assertSame(0x04, $tag);
        self::assertSame('hello', $value);
        self::assertSame(7, $nextOffset);
    }

    public function testReadTlvReadsAtANonZeroOffset(): void
    {
        [$tag, $value, $nextOffset] = Der::readTlv("\xFF\xFF\x04\x05hello", 2);

        self::assertSame(0x04, $tag);
        self::assertSame('hello', $value);
        self::assertSame(9, $nextOffset);
    }

    public function testReadTlvReadsALongFormLengthTlv(): void
    {
        $value = str_repeat('a', 200);

        [$tag, $decodedValue, $nextOffset] = Der::readTlv("\x04\x81\xC8" . $value, 0);

        self::assertSame(0x04, $tag);
        self::assertSame($value, $decodedValue);
        self::assertSame(203, $nextOffset);
    }

    public function testReadTlvRejectsATruncatedTlv(): void
    {
        $this->expectException(InvalidArgumentException::class);
        Der::readTlv("\x04\x05hi", 0);
    }

    public function testBytesFromPublicKeyPemStripsTheHeaderFooterAndNewlinesAndDecodesTheBase64Content(): void
    {
        $der = Der::bytesFromPublicKeyPem(
            "-----BEGIN PUBLIC KEY-----\n"
            . base64_encode('not a real public key') . "\n"
            . "-----END PUBLIC KEY-----\n",
        );

        self::assertSame('not a real public key', $der);
    }

    public function testWriteTlvRoundTripsAShortFormLengthValue(): void
    {
        $encoded = Der::writeTlv(0x04, 'hello');

        self::assertSame("\x04\x05hello", $encoded);
        [$tag, $value] = Der::readTlv($encoded, 0);
        self::assertSame(0x04, $tag);
        self::assertSame('hello', $value);
    }

    public function testWriteTlvRoundTripsALongFormLengthValue(): void
    {
        $value   = str_repeat('a', 200);
        $encoded = Der::writeTlv(0x04, $value);

        self::assertSame("\x04\x81\xC8" . $value, $encoded);
        [$tag, $decodedValue] = Der::readTlv($encoded, 0);
        self::assertSame(0x04, $tag);
        self::assertSame($value, $decodedValue);
    }
}
