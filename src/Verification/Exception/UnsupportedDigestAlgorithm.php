<?php

declare(strict_types=1);

namespace ThePhpFoundation\Attestation\Verification\Exception;

use function sprintf;

class UnsupportedDigestAlgorithm extends FailedToVerifyArtifact
{
    public static function fromAlgorithm(string $algorithm): self
    {
        return new self(sprintf(
            'Unsupported message digest algorithm "%s"; only SHA2_256 is currently supported',
            $algorithm,
        ));
    }
}
