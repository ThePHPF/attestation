<?php

declare(strict_types=1);

namespace ThePhpFoundation\UnitTest\Attestation;

use PHPUnit\Framework\TestCase;
use ThePhpFoundation\Attestation\MessageSignature;
use ThePhpFoundation\Attestation\Verification\Exception\UnsupportedDigestAlgorithm;

use function base64_decode;

/** @covers \ThePhpFoundation\Attestation\MessageSignature */
final class MessageSignatureTest extends TestCase
{
    public function testFromBundleMessageSignature(): void
    {
        $messageSignature = MessageSignature::fromBundleMessageSignature([
            'messageDigest' => [
                'algorithm' => 'SHA2_256',
                'digest' => 'oM/HEnHW4njlfNMy/5V8P3BD/do1TEy7GQow1W76Ab8=',
            ],
            'signature' => 'MEQCIFOpaXKWvvBDwThDjTHX7tFF8liRoSxLZIsSeoUM/6D4AiBxV9/RnTMMw1t6nniX0rCuwrf8Vh+feLFu99m4ir+3yA==',
        ]);

        self::assertSame(
            'a0cfc71271d6e278e57cd332ff957c3f7043fdda354c4cbb190a30d56efa01bf',
            $messageSignature->digestHex,
        );
        self::assertSame(
            base64_decode('MEQCIFOpaXKWvvBDwThDjTHX7tFF8liRoSxLZIsSeoUM/6D4AiBxV9/RnTMMw1t6nniX0rCuwrf8Vh+feLFu99m4ir+3yA=='),
            $messageSignature->signature,
        );
    }

    public function testFromBundleMessageSignatureRejectsUnsupportedDigestAlgorithm(): void
    {
        $this->expectException(UnsupportedDigestAlgorithm::class);

        MessageSignature::fromBundleMessageSignature([
            'messageDigest' => [
                'algorithm' => 'SHA3_256',
                'digest' => 'oM/HEnHW4njlfNMy/5V8P3BD/do1TEy7GQow1W76Ab8=',
            ],
            'signature' => 'MEQCIFOpaXKWvvBDwThDjTHX7tFF8liRoSxLZIsSeoUM/6D4AiBxV9/RnTMMw1t6nniX0rCuwrf8Vh+feLFu99m4ir+3yA==',
        ]);
    }
}
