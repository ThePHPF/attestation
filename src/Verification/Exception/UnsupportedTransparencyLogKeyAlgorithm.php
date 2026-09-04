<?php

declare(strict_types=1);

namespace ThePhpFoundation\Attestation\Verification\Exception;

use function sprintf;

class UnsupportedTransparencyLogKeyAlgorithm extends FailedToVerifyArtifact
{
    public static function fromKeyDetails(string $keyDetails): self
    {
        return new self(sprintf(
            'Unsupported transparency log key algorithm "%s"; only PKIX_ECDSA_P256_SHA_256 and PKIX_ED25519 are currently supported',
            $keyDetails,
        ));
    }
}
