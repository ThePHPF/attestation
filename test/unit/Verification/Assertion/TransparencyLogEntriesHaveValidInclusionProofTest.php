<?php

declare(strict_types=1);

namespace ThePhpFoundation\UnitTest\Attestation\Verification\Assertion;

use PHPUnit\Framework\TestCase;
use ThePhpFoundation\Attestation\Bundle;
use ThePhpFoundation\Attestation\FilenameWithChecksum;
use ThePhpFoundation\Attestation\Verification\Assertion\TransparencyLogEntriesHaveValidInclusionProof;
use ThePhpFoundation\Attestation\Verification\Exception\InvalidMerkleInclusionProof;

use function array_map;
use function base64_encode;
use function hash;

/** @covers \ThePhpFoundation\Attestation\Verification\Assertion\TransparencyLogEntriesHaveValidInclusionProof */
final class TransparencyLogEntriesHaveValidInclusionProofTest extends TestCase
{
    private const LEAF_BODY_0 = 'leaf zero';
    private const LEAF_BODY_1 = 'leaf one';

    private static function leafHash(string $body): string
    {
        return hash('sha256', "\x00" . $body, true);
    }

    private static function nodeHash(string $left, string $right): string
    {
        return hash('sha256', "\x01" . $left . $right, true);
    }

    /** @param list<string> $proofHashes */
    private static function bundleWithInclusionProof(?array $proofHashes, string $rootHash): Bundle
    {
        $tlogEntry = [
            'logIndex' => '1',
            'kindVersion' => ['kind' => 'hashedrekord', 'version' => '0.0.1'],
            'logId' => ['keyId' => base64_encode('not a real log id')],
            'canonicalizedBody' => base64_encode(self::LEAF_BODY_0),
        ];

        if ($proofHashes !== null) {
            $tlogEntry['inclusionProof'] = [
                'logIndex' => '0',
                'treeSize' => '2',
                'rootHash' => base64_encode($rootHash),
                'hashes' => array_map(static fn (string $hash): string => base64_encode($hash), $proofHashes),
                'checkpoint' => ['envelope' => 'irrelevant'],
            ];
        }

        return Bundle::fromBundle([
            'mediaType' => 'application/vnd.dev.sigstore.bundle+json;version=0.3',
            'verificationMaterial' => [
                'certificate' => ['rawBytes' => base64_encode('not a real certificate')],
                'tlogEntries' => [$tlogEntry],
            ],
            'messageSignature' => [
                'messageDigest' => [
                    'algorithm' => 'SHA2_256',
                    'digest' => base64_encode('not a real digest'),
                ],
                'signature' => base64_encode('not a real signature'),
            ],
        ]);
    }

    public function testAcceptsAValidTwoLeafInclusionProof(): void
    {
        $leaf0 = self::leafHash(self::LEAF_BODY_0);
        $leaf1 = self::leafHash(self::LEAF_BODY_1);
        $root  = self::nodeHash($leaf0, $leaf1);

        $this->expectNotToPerformAssertions();
        (new TransparencyLogEntriesHaveValidInclusionProof())->assert(
            FilenameWithChecksum::fromFilenameAndChecksum('irrelevant', 'irrelevant'),
            0,
            self::bundleWithInclusionProof([$leaf1], $root),
        );
    }

    public function testRejectsAMissingInclusionProof(): void
    {
        $this->expectException(InvalidMerkleInclusionProof::class);
        (new TransparencyLogEntriesHaveValidInclusionProof())->assert(
            FilenameWithChecksum::fromFilenameAndChecksum('irrelevant', 'irrelevant'),
            0,
            self::bundleWithInclusionProof(null, ''),
        );
    }

    public function testRejectsAProofWithTheWrongNumberOfHashes(): void
    {
        $leaf0 = self::leafHash(self::LEAF_BODY_0);
        $leaf1 = self::leafHash(self::LEAF_BODY_1);
        $root  = self::nodeHash($leaf0, $leaf1);

        $this->expectException(InvalidMerkleInclusionProof::class);
        (new TransparencyLogEntriesHaveValidInclusionProof())->assert(
            FilenameWithChecksum::fromFilenameAndChecksum('irrelevant', 'irrelevant'),
            0,
            self::bundleWithInclusionProof([], $root),
        );
    }

    public function testRejectsAProofWhoseComputedRootDoesNotMatchTheClaimedRootHash(): void
    {
        $leaf0         = self::leafHash(self::LEAF_BODY_0);
        $leaf1         = self::leafHash(self::LEAF_BODY_1);
        $corruptedRoot = self::nodeHash($leaf1, $leaf0);

        $this->expectException(InvalidMerkleInclusionProof::class);
        (new TransparencyLogEntriesHaveValidInclusionProof())->assert(
            FilenameWithChecksum::fromFilenameAndChecksum('irrelevant', 'irrelevant'),
            0,
            self::bundleWithInclusionProof([$leaf1], $corruptedRoot),
        );
    }
}
