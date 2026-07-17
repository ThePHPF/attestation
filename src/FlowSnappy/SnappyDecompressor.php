<?php

/**
 * Copyright (c) 2020-present Flow PHP
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * Source: https://github.com/flow-php/snappy/blob/d42c40b627144033f844103ec5ae0c1f325314e1/src/Flow/Snappy/SnappyDecompressor.php
 *
 * Modified to work with PHP 7.4
 */

declare(strict_types=1);

namespace ThePhpFoundation\Attestation\FlowSnappy;

use function array_fill;
use function count;

/**
 * @internal This class is not meant to be used by library users. Please use Flow\Snappy\Snappy instead.
 */
final class SnappyDecompressor
{
    private const WORD_MASK = [0, 0xFF, 0xFFFF, 0xFFFFFF, 0xFFFFFFFF];

    private int $arrayLength;

    private int $pos = 0;

    private array $array;

    /**
     * @param array<int> $array
     */
    public function __construct(array $array)
    {
        $this->array = $array;
        $this->arrayLength = count($this->array);
    }

    public function readUncompressedLength(): int
    {
        $result = 0;
        $shift = 0;

        while ($shift < 32 && $this->pos < $this->arrayLength) {
            $c = $this->array[$this->pos];
            $this->pos++;
            $val = $c & 0x7F;

            if ((($val << $shift) >> $shift) !== $val) {
                return -1;
            }
            $result |= $val << $shift;

            if ($c < 128) {
                return $result;
            }
            $shift += 7;
        }

        return -1;
    }

    /**
     * @param array<int> $outBuffer
     */
    public function uncompressToBuffer(array &$outBuffer): bool
    {
        $uncompressedLength = $this->readUncompressedLength();

        if ($uncompressedLength < 0) {
            return false;
        }

        $outBuffer = array_fill(0, $uncompressedLength, 0);
        $pos = $this->pos;
        $outPos = 0;
        $len = $offset = 0;

        while ($pos < count($this->array)) {
            $c = $this->array[$pos];
            $pos++;

            if (($c & 0x3) === 0) {
                // Literal
                $len = ($c >> 2) + 1;

                if ($len > 60) {
                    if (($pos + 3) >= $this->arrayLength) {
                        return false;
                    }
                    $smallLen = $len - 60;
                    $len =
                        $this->array[$pos]
                        + ($this->array[$pos + 1] << 8)
                        + ($this->array[$pos + 2] << 16)
                        + ($this->array[$pos + 3] << 24);
                    $len = ($len & self::WORD_MASK[$smallLen]) + 1;
                    $pos += $smallLen;
                }

                if (($pos + $len) > $this->arrayLength) {
                    return false;
                }
                $this->copyBytes($this->array, $pos, $outBuffer, $outPos, (int) $len);
                $pos += $len;
                $outPos += $len;
            } else {
                switch ($c & 0x3) {
                    case 1:
                        $len = (($c >> 2) & 0x7) + 4;
                        $offset = $this->array[$pos] + (($c >> 5) << 8);
                        $pos++;

                        break;
                    case 2:
                        if (($pos + 1) >= $this->arrayLength) {
                            return false;
                        }
                        $len = ($c >> 2) + 1;
                        $offset = $this->array[$pos] + ($this->array[$pos + 1] << 8);
                        $pos += 2;

                        break;
                    case 3:
                        if (($pos + 3) >= $this->arrayLength) {
                            return false;
                        }
                        $len = ($c >> 2) + 1;
                        $offset =
                            $this->array[$pos]
                            + ($this->array[$pos + 1] << 8)
                            + ($this->array[$pos + 2] << 16)
                            + ($this->array[$pos + 3] << 24);
                        $pos += 4;

                        break;
                }

                if ($offset === 0 || $offset > $outPos) {
                    return false;
                }
                $this->selfCopyBytes($outBuffer, $outPos, $offset, $len);
                $outPos += $len;
            }
        }

        return true;
    }

    /**
     * @param array<int> $fromArray
     * @param array<int> $toArray
     */
    private function copyBytes(array $fromArray, int $fromPos, array &$toArray, int $toPos, int $length): void
    {
        for ($i = 0; $i < $length; $i++) {
            $toArray[$toPos + $i] = $fromArray[$fromPos + $i];
        }
    }

    /**
     * @param array<int> $array
     */
    private function selfCopyBytes(array &$array, int $pos, int $offset, int $length): void
    {
        for ($i = 0; $i < $length; $i++) {
            $array[$pos + $i] = $array[$pos - $offset + $i];
        }
    }
}
