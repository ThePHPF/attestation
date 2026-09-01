<?php

declare(strict_types=1);

namespace ThePhpFoundation\Attestation\Command;

use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Exception\RuntimeException;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use ThePhpFoundation\Attestation\AttestationException;
use ThePhpFoundation\Attestation\BundleSource\OnDiskBundle;
use ThePhpFoundation\Attestation\FilenameWithChecksum;
use ThePhpFoundation\Attestation\FulcioSigstoreOidExtensions;
use ThePhpFoundation\Attestation\Verification\VerifyBundleWithOpenSsl;
use Webmozart\Assert\Assert;

use function sprintf;
use function str_starts_with;
use function strlen;
use function substr;

/**
 * Implements the `verify-bundle` command of the Sigstore conformance CLI protocol.
 *
 * @link https://github.com/sigstore/sigstore-conformance/blob/main/docs/cli_protocol.md#verify-bundle
 */
class VerifyBundle extends Command
{
    private const SHA256_PREFIX = 'sha256:';

    /** @var string */
    // phpcs:ignore SlevomatCodingStandard.TypeHints.PropertyTypeHint.MissingNativeTypeHint
    protected static $defaultName = 'verify-bundle';

    protected function configure(): void
    {
        $this->addArgument('artifact', InputArgument::REQUIRED, 'The artifact file to verify, or a sha256:<digest>');
        $this->addOption('bundle', null, InputOption::VALUE_REQUIRED, 'Path to the Sigstore bundle file');
        $this->addOption('certificate-identity', null, InputOption::VALUE_REQUIRED, 'The expected signing certificate identity');
        $this->addOption('certificate-oidc-issuer', null, InputOption::VALUE_REQUIRED, 'The expected OIDC issuer of the signing certificate');
        $this->addOption('trusted-root', null, InputOption::VALUE_REQUIRED, 'Path to a custom trusted root file');
        $this->addOption('staging', null, InputOption::VALUE_NONE, 'Verify against the Sigstore staging environment (not currently supported)');
    }

    public function execute(InputInterface $input, OutputInterface $output): int
    {
        $artifact              = $this->readArtifactArgument($input);
        $bundle                = $this->readBundleOption($input);
        $certificateIdentity   = $this->readCertificateIdentityOption($input);
        $certificateOidcIssuer = $this->readCertificateOidcIssuerOption($input);
        $trustedRoot           = $this->readTrustedRootOption($input);

        if (str_starts_with($artifact, self::SHA256_PREFIX)) {
            $checksum = substr($artifact, strlen(self::SHA256_PREFIX));
            Assert::stringNotEmpty($checksum);

            $file = FilenameWithChecksum::fromFilenameAndChecksum($artifact, $checksum);
        } else {
            Assert::fileExists($artifact);
            $file = FilenameWithChecksum::fromFilename($artifact);
        }

        $output->writeln(sprintf('Verifying bundle <info>%s</info> for <info>%s</info>...', $bundle, $artifact));

        try {
            $bundles    = (new OnDiskBundle($bundle))->getBundles($file);
            $extensions = [FulcioSigstoreOidExtensions::ISSUER_V2 => $certificateOidcIssuer];

            $verifier = $trustedRoot !== null
                ? VerifyBundleWithOpenSsl::withTrustedRootFile($trustedRoot, $extensions, $certificateIdentity)
                : VerifyBundleWithOpenSsl::factory($extensions, $certificateIdentity);

            $verifier->verify($bundles, $file);
        } catch (AttestationException $failure) {
            $output->writeln(sprintf('❌ %s', $failure->getMessage()));

            return self::FAILURE;
        }

        $output->writeln('✅ Verified');

        return self::SUCCESS;
    }

    /** @return non-empty-string */
    private function readArtifactArgument(InputInterface $input): string
    {
        $artifact = $input->getArgument('artifact');
        Assert::stringNotEmpty($artifact);

        return $artifact;
    }

    /** @return non-empty-string */
    private function readBundleOption(InputInterface $input): string
    {
        $bundle = $input->getOption('bundle');
        Assert::nullOrString($bundle);

        if ($bundle === null || $bundle === '') {
            throw new RuntimeException('Specify --bundle=path/to/bundle.json');
        }

        return $bundle;
    }

    /** @return non-empty-string */
    private function readCertificateIdentityOption(InputInterface $input): string
    {
        $certificateIdentity = $input->getOption('certificate-identity');
        Assert::nullOrString($certificateIdentity);

        if ($certificateIdentity === null || $certificateIdentity === '') {
            throw new RuntimeException('Specify --certificate-identity=...');
        }

        return $certificateIdentity;
    }

    /** @return non-empty-string */
    private function readCertificateOidcIssuerOption(InputInterface $input): string
    {
        $certificateOidcIssuer = $input->getOption('certificate-oidc-issuer');
        Assert::nullOrString($certificateOidcIssuer);

        if ($certificateOidcIssuer === null || $certificateOidcIssuer === '') {
            throw new RuntimeException('Specify --certificate-oidc-issuer=https://...');
        }

        return $certificateOidcIssuer;
    }

    /** @return non-empty-string|null */
    private function readTrustedRootOption(InputInterface $input): string|null
    {
        $trustedRoot = $input->getOption('trusted-root');
        Assert::nullOrString($trustedRoot);

        return $trustedRoot === null || $trustedRoot === '' ? null : $trustedRoot;
    }
}
