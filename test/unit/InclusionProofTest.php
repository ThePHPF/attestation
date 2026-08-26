<?php

declare(strict_types=1);

namespace ThePhpFoundation\UnitTest\Attestation;

use PHPUnit\Framework\TestCase;
use ThePhpFoundation\Attestation\InclusionProof;

use function base64_decode;

/** @covers \ThePhpFoundation\Attestation\InclusionProof */
final class InclusionProofTest extends TestCase
{
    public function testFromBundleInclusionProof(): void
    {
        $inclusionProof = InclusionProof::fromBundleInclusionProof([
            'logIndex' => '339175637',
            'rootHash' => 'AhbZoVyv2FfnyQjQoGoj8crpY4R1tWuJiLVIUJxmGB4=',
            'treeSize' => '339175655',
            'hashes' => [
                '+cZUU5T9fPeBM0sh9Tr6pkevLIqAm2g7wQjSeibo4Vg=',
                'h7VJtejEapYJ0lVmwmrZd8GFeWKSibdiJmP+aLD8/kc=',
            ],
            'checkpoint' => ['envelope' => "rekor.sigstore.dev - 1193050959916656506\n339175655\nAhbZoVyv2FfnyQjQoGoj8crpY4R1tWuJiLVIUJxmGB4=\n\n— rekor.sigstore.dev wNI9ajBGAiEAhEsbDtU0G6tkfpxcTPi5Q0Tsi/Z85DBcGst+iLS6NncCIQDPlvrm+OVQyT31gOp90Mh74np6cFEryT2ybYVWq7CNRw==\n"],
        ]);

        self::assertSame(339175637, $inclusionProof->logIndex());
        self::assertSame(base64_decode('AhbZoVyv2FfnyQjQoGoj8crpY4R1tWuJiLVIUJxmGB4='), $inclusionProof->rootHash());
        self::assertSame(339175655, $inclusionProof->treeSize());
        self::assertCount(2, $inclusionProof->hashes());
        self::assertSame(base64_decode('+cZUU5T9fPeBM0sh9Tr6pkevLIqAm2g7wQjSeibo4Vg='), $inclusionProof->hashes()[0]);
        self::assertSame(base64_decode('h7VJtejEapYJ0lVmwmrZd8GFeWKSibdiJmP+aLD8/kc='), $inclusionProof->hashes()[1]);
        self::assertSame(
            "rekor.sigstore.dev - 1193050959916656506\n339175655\nAhbZoVyv2FfnyQjQoGoj8crpY4R1tWuJiLVIUJxmGB4=\n\n— rekor.sigstore.dev wNI9ajBGAiEAhEsbDtU0G6tkfpxcTPi5Q0Tsi/Z85DBcGst+iLS6NncCIQDPlvrm+OVQyT31gOp90Mh74np6cFEryT2ybYVWq7CNRw==\n",
            $inclusionProof->checkpointEnvelope(),
        );
    }

    public function testFromBundleInclusionProofWithoutCheckpoint(): void
    {
        $inclusionProof = InclusionProof::fromBundleInclusionProof([
            'logIndex' => '1',
            'rootHash' => 'AhbZoVyv2FfnyQjQoGoj8crpY4R1tWuJiLVIUJxmGB4=',
            'treeSize' => '2',
            'hashes' => [],
        ]);

        self::assertNull($inclusionProof->checkpointEnvelope());
        self::assertSame([], $inclusionProof->hashes());
    }
}
