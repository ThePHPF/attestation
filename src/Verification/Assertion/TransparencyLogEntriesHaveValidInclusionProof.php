<?php

declare(strict_types=1);

namespace ThePhpFoundation\Attestation\Verification\Assertion;

use ThePhpFoundation\Attestation\Bundle;
use ThePhpFoundation\Attestation\FilenameWithChecksum;
use ThePhpFoundation\Attestation\Verification\Exception\InvalidMerkleInclusionProof;

use function count;
use function hash;
use function hash_equals;

/**
 * @link https://www.rfc-editor.org/rfc/rfc6962#section-2.1.1
 * @link https://github.com/transparency-dev/merkle/blob/main/proof/verify.go
 */
final class TransparencyLogEntriesHaveValidInclusionProof implements VerifyBundleCheck
{
    public function assert(FilenameWithChecksum $file, int $bundleIndex, Bundle $bundle): void
    {
        foreach ($bundle->transparencyLogEntries() as $transparencyLogEntry) {
            $inclusionProof = $transparencyLogEntry->inclusionProof();
            if ($inclusionProof === null) {
                throw InvalidMerkleInclusionProof::forIndex($bundleIndex);
            }

            $index = $inclusionProof->logIndex();
            $size  = $inclusionProof->treeSize();
            $proof = $inclusionProof->hashes();

            $inner  = $this->bitLength($index ^ $size - 1);
            $border = $this->popCount($index >> $inner);

            if (count($proof) !== $inner + $border) {
                throw InvalidMerkleInclusionProof::forIndex($bundleIndex);
            }

            $seed = $this->merkleLeafHash($transparencyLogEntry->canonicalizedBody());
            for ($i = 0; $i < $inner; $i++) {
                if ((($index >> $i) & 1) === 0) {
                    $seed = $this->merkleNodeHash($seed, $proof[$i]);
                } else {
                    $seed = $this->merkleNodeHash($proof[$i], $seed);
                }
            }

            for ($i = $inner; $i < count($proof); $i++) {
                $seed = $this->merkleNodeHash($proof[$i], $seed);
            }

            if (! hash_equals($inclusionProof->rootHash(), $seed)) {
                throw InvalidMerkleInclusionProof::forIndex($bundleIndex);
            }
        }
    }

    private function merkleLeafHash(string $canonicalizedBody): string
    {
        return hash('sha256', "\x00" . $canonicalizedBody, true);
    }

    private function merkleNodeHash(string $left, string $right): string
    {
        return hash('sha256', "\x01" . $left . $right, true);
    }

    private function bitLength(int $n): int
    {
        $length = 0;
        while ($n > 0) {
            $n >>= 1;
            $length++;
        }

        return $length;
    }

    private function popCount(int $n): int
    {
        $count = 0;
        while ($n > 0) {
            $count += $n & 1;
            $n    >>= 1;
        }

        return $count;
    }
}
