<?php
/**
 * This file is part of the LdapToolsBundle package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace spec\LdapTools\Bundle\LdapToolsBundle\Command;

use LdapTools\Bundle\LdapToolsBundle\Command\SslCertificateCommand;
use PhpSpec\ObjectBehavior;
use Symfony\Component\Console\Helper\HelperSet;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

class SslCertificateCommandSpec extends ObjectBehavior
{
    function let(InputInterface $input, OutputInterface $output, HelperSet $helperSet)
    {
        $this->setHelperSet($helperSet);
        $input->getOption('server')->willReturn(null);
        $input->getOption('port')->willReturn(389);
    }

    function it_is_initializable()
    {
        $this->shouldHaveType(SslCertificateCommand::class);
    }

    function it_should_require_a_server_name($input, $output)
    {
        $this->shouldThrow(new \Exception("You must enter a server name."))->duringExecute($input, $output);
    }
}
