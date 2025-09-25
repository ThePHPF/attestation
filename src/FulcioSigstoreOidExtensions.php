<?php

declare(strict_types=1);

namespace ThePhpFoundation\Attestation;

/**
 * Some of the Fulcio Sigstore OID extensions.
 *
 * @link https://github.com/sigstore/fulcio/blob/main/docs/oid-info.md#136141572641--fulcio
 */
final class FulcioSigstoreOidExtensions
{
    /** @link https://github.com/sigstore/fulcio/blob/main/docs/oid-info.md#1361415726418--issuer-v2 */
    public const ISSUER_V2 = '1.3.6.1.4.1.57264.1.8';

    /** @link https://github.com/sigstore/fulcio/blob/main/docs/oid-info.md#13614157264112--source-repository-uri */
    public const SOURCE_REPOSITORY_URI = '1.3.6.1.4.1.57264.1.12';

    /** @link https://github.com/sigstore/fulcio/blob/main/docs/oid-info.md#13614157264116--source-repository-owner-uri */
    public const SOURCE_REPOSITORY_OWNER_URI = '1.3.6.1.4.1.57264.1.16';
}
