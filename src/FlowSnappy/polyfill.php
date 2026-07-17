<?php

declare(strict_types=1);

use ThePhpFoundation\Attestation\FlowSnappy\Snappy;

if (! function_exists('snappy_uncompress')) {
    function snappy_uncompress(string $compressedBundle): string
    {
        return (new Snappy())->uncompress($compressedBundle);
    }
}
