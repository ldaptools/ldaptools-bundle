<?php
/**
 * This file is part of the LdapToolsBundle package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace LdapTools\Bundle\LdapToolsBundle\Command;

use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use LdapTools\Utilities\LdapUtilities;

/**
 * Retrieves the LDAP SSL certificate from a given server and generates the certificate bundle for it.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class SslCertificateCommand extends Command
{
    /**
     * {@inheritDoc}
     */
    protected function configure()
    {
        $this
            ->setName('ldaptools:generate:sslcert')
            ->addOption('server', null, InputOption::VALUE_REQUIRED, 'The LDAP server name.')
            ->addOption('port', null, InputOption::VALUE_OPTIONAL, 'The LDAP port number.', 389)
            ->setDescription('Retrieves the LDAP SSL/TLS certificate from a server and generates the certificate bundle.');
    }

    /**
     * {@inheritdoc}
     */
    public function execute(InputInterface $input, OutputInterface $output)
    {
        $server = trim($input->getOption('server'));
        $port = (int) $input->getOption('port');
        if (!$server) {
            throw new \Exception('You must enter a server name.');
        }

        $certs = LdapUtilities::getLdapSslCertificates($server, $port);
        $bundle = $certs['peer_certificate'].implode('', $certs['peer_certificate_chain']);
        if (empty($bundle)) {
            $output->writeln(sprintf('<error>Unable to retrieve SSL certificate from %s on port %s.</error>', $server, $port));

            return 1;
        }
        $output->writeln($bundle);

        return 0;
    }
}
