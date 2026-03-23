<?php

declare(strict_types=1);

namespace ThePhpFoundation\Attestation\Command;

use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use ThePhpFoundation\Attestation\FilenameWithChecksum;
use ThePhpFoundation\Attestation\Verification\VerifyAttestationWithOpenSsl;

class Verify extends Command
{
    protected static $defaultName = 'verify';

    protected function configure(): void
    {
        // @todo we should probably make this match https://github.com/sigstore/sigstore-conformance/blob/main/docs/cli_protocol.md#verify
        $this->addArgument('filename', InputArgument::REQUIRED, 'The filename to verify');
        $this->addOption('owner', 'o', InputOption::VALUE_REQUIRED, 'The owner to verify against');
    }

    public function execute(InputInterface $input, OutputInterface $output): int
    {
        $file = $input->getArgument('filename');
        $owner = (string) $input->getOption('owner');

        if ($owner === '') {
            $output->writeln('Specify owner, e.g. --owner=blah');

            return 1;
        }

        $output->writeln(sprintf(
            'Verifying file: <info>%s</info>, for owner <info>%s</info>...',
            $file,
            $owner,
        ));

        $verifier = VerifyAttestationWithOpenSsl::factory();
        $verifier->verify(
            FilenameWithChecksum::fromFilename($file),
            $owner,
            basename($file), // @todo this might not match the record!
            [], // @todo what should we verify here?
        );

        $output->writeln('✅ Verified');

        return 0;
    }
}
