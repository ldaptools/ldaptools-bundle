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

use LdapTools\Bundle\LdapToolsBundle\Command\ConfigCommand;
use LdapTools\Bundle\LdapToolsBundle\Factory\LdapFactory;
use LdapTools\Connection\LdapConnection;
use LdapTools\Connection\LdapServerPool;
use LdapTools\DomainConfiguration;
use LdapTools\Exception\LdapConnectionException;
use LdapTools\Object\LdapObject;
use LdapTools\Operation\AuthenticationResponse;
use PhpSpec\ObjectBehavior;
use Prophecy\Argument;
use Symfony\Component\Console\Helper\HelperSet;
use Symfony\Component\Console\Helper\QuestionHelper;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Question\ChoiceQuestion;
use Symfony\Component\Console\Question\Question;

class ConfigCommandSpec extends ObjectBehavior
{
    protected $askRetry;
    protected $askServer;
    protected $askDomain;
    protected $askEncryption;
    protected $askUsername;
    protected $askPassword;
    protected $verifyPassword;
    protected $tryAnotherPassword;
    protected $askShowConfig;

    function let(InputInterface $input, OutputInterface $output, HelperSet $helperSet, LdapFactory $factory, LdapServerPool $serverPool, LdapConnection $connection, QuestionHelper $questionHelper)
    {
        $this->setConnectionFactory($factory);
        $this->setLdapServerPool($serverPool);
        $this->setHelperSet($helperSet);
        $helperSet->get('question')->willReturn($questionHelper);

        $domainCfg = (new DomainConfiguration('foo.bar'))
            ->setBaseDn('dc=foo,dc=bar')
            ->setServers(['foo'])
            ->setUsername('foo')
            ->setPassword('12345')
            ->setUseTls(true);
        $factory->getConfig('')->willReturn($domainCfg);
        $factory->getConnection(Argument::any())->willReturn($connection);

        $input->getOption('domain')->willReturn(null);
        $input->getOption('server')->willReturn(null);
        $input->getOption('username')->willReturn(null);
        $input->getOption('password')->willReturn(null);
        $input->getOption('port')->willReturn(389);
        $input->getOption('silent')->willReturn(false);
        $input->getOption('non-interactive')->willReturn(false);
        $input->getOption('show-config')->willReturn(false);
        $input->getOption('use-ssl')->willReturn(false);
        $input->getOption('use-tls')->willReturn(false);

        $connection->getRootDse()->willReturn(new LdapObject(['defaultNamingContext' => 'dc=foo,dc=bar']));
        $connection->getConfig()->willReturn($domainCfg);
        $connection->execute(Argument::any())->willReturn(new AuthenticationResponse(true));
        $serverPool->setConfig(Argument::any())->willReturn($serverPool);
        $serverPool->getServer()->willReturn('foo');

        $output->writeln(Argument::any())->willReturn(null);
        $this->askRetry = Argument::that(function($question) {
            /** @var Question $question */
            return preg_match('/Try again/i', $question->getQuestion());
        });
        $this->askServer = Argument::that(function($question) {
            /** @var Question $question */
            return preg_match('/Enter a server name/i', $question->getQuestion());
        });
        $this->askDomain = Argument::that(function($question) {
            /** @var Question $question */
            return preg_match('/Enter a domain name/i', $question->getQuestion());
        });
        $this->askEncryption = Argument::that(function($question) {
            /** @var ChoiceQuestion $question */
            return preg_match('/Encryption is currently not enabled/i', $question->getQuestion());
        });
        $this->askUsername = Argument::that(function($question) {
            /** @var Question $question */
            return preg_match('/Enter the LDAP username/i', $question->getQuestion());
        });
        $this->askPassword = Argument::that(function($question) {
            /** @var Question $question */
            return preg_match('/Enter the LDAP password/i', $question->getQuestion());
        });
        $this->verifyPassword = Argument::that(function($question) {
            /** @var Question $question */
            return preg_match('/Enter the password again/i', $question->getQuestion());
        });
        $this->tryAnotherPassword = Argument::that(function($question) {
            /** @var Question $question */
            return preg_match('/Try a different username\/password?/i', $question->getQuestion());
        });
        $this->askShowConfig = Argument::that(function($question) {
            /** @var Question $question */
            return preg_match('/Show the generated config (includes password)?/i', $question->getQuestion());
        });

        $questionHelper->ask($input, $output, $this->askServer)->willReturn('foo');
        $questionHelper->ask($input, $output, $this->askEncryption)->willReturn('TLS');
        $questionHelper->ask($input, $output, $this->askUsername)->willReturn('foo');
        $questionHelper->ask($input, $output, $this->askPassword)->willReturn('12345');
        $questionHelper->ask($input, $output, $this->verifyPassword)->willReturn('12345');
        $questionHelper->ask($input, $output, $this->askShowConfig)->willReturn(false);
        $questionHelper->ask($input, $output, $this->askRetry)->willReturn(false);
    }

    function it_is_initializable()
    {
        $this->shouldHaveType(ConfigCommand::class);
    }

    function it_should_not_allow_both_the_tls_and_ssl_switches($input, $output)
    {
        $input->getOption('use-ssl')->willReturn(true);
        $input->getOption('use-tls')->willReturn(true);

        $this->shouldThrow(new \LogicException("You cannot use both the ssl and tls option. Generally you want --use-tls."))->duringExecute($input, $output);
    }

    function it_should_require_a_server_or_domain_if_no_interaction_is_specified($input, $output)
    {
        $input->getOption('non-interactive')->willReturn(true);

        $this->shouldThrow(new \LogicException("You must enter a server or domain when not in interactive mode."))->duringExecute($input, $output);
    }

    function it_should_require_a_username_and_password_if_no_interaction_is_specified($input, $output)
    {
        $input->getOption('non-interactive')->willReturn(true);

        $input->getOption('server')->willReturn('foo');
        $this->shouldThrow(new \LogicException("You must enter a username and password when not in interactive mode."))->duringExecute($input, $output);

        $input->getOption('domain')->willReturn('bar');
        $this->shouldThrow(new \LogicException("You must enter a username and password when not in interactive mode."))->duringExecute($input, $output);

        $input->getOption('username')->willReturn('foobar');
        $this->shouldThrow(new \LogicException("You must enter a username and password when not in interactive mode."))->duringExecute($input, $output);
    }

    function it_should_prompt_for_a_server_name_if_not_supplied($input, $output, $questionHelper, $serverPool)
    {
        $serverPool->getServer()->shouldBeCalled()->willThrow(new LdapConnectionException());
        $questionHelper->ask($input, $output, $this->askServer)->shouldBeCalled()->willReturn('foo');

        $this->execute($input, $output);
    }

    function it_should_prompt_for_a_domain_name_if_no_server_is_entered($input, $output, $questionHelper, $serverPool)
    {
        $serverPool->getServer()->shouldBeCalled()->willThrow(new LdapConnectionException());
        $questionHelper->ask($input, $output, $this->askServer)->shouldBeCalled()->willReturn('');
        $questionHelper->ask($input, $output, $this->askDomain)->shouldBeCalled()->willReturn('foo.bar');

        $this->execute($input, $output);
    }

    function it_should_prompt_for_an_encryption_type_and_username_and_password($input, $output, $questionHelper)
    {
        $questionHelper->ask($input, $output, $this->askEncryption)->shouldBeCalled()->willReturn('TLS');
        $questionHelper->ask($input, $output, $this->askUsername)->shouldBeCalled()->willReturn('foo');
        $questionHelper->ask($input, $output, $this->askPassword)->shouldBeCalled()->willReturn('12345');
        $questionHelper->ask($input, $output, $this->verifyPassword)->shouldBeCalled()->willReturn('12345');

        $this->execute($input, $output);
    }

    function it_should_ask_to_reenter_the_password_if_they_dont_match_or_auth_fails($input, $output, $questionHelper, $connection)
    {
        $questionHelper->ask($input, $output, $this->askPassword)->shouldBeCalledTimes(2)->willReturn('12345', '12345');
        $questionHelper->ask($input, $output, $this->verifyPassword)->shouldBeCalledTimes(2)->willReturn('password', '12345');
        $connection->execute(Argument::any())->willReturn(new AuthenticationResponse(false));

        $output->writeln(Argument::containingString('Passwords do not match'))->shouldBeCalled();
        $questionHelper->ask($input, $output, $this->tryAnotherPassword)->shouldBeCalled()->willReturn(false);

        $this->execute($input, $output)->shouldBeEqualTo(1);
    }

    function it_should_prompt_to_continue_without_encryption_if_it_wasnt_successful($questionHelper, $input, $output, $connection)
    {
        $connection->getRootDse()->willReturn(new LdapObject(['defaultNamingContext' => 'dc=foo,dc=bar']), null);

        $questionHelper->ask($input, $output, $this->askEncryption)->shouldBeCalled()->willReturn('TLS');
        $questionHelper->ask($input, $output, Argument::that(function($question) {
            /** @var Question $question */
            return preg_match('/Continue without encryption?/i', $question->getQuestion());
        }))->shouldBeCalled()->willReturn(true);

        $this->execute($input, $output);
    }

    function it_should_prompt_to_retry_if_it_cannot_connect_to_the_server_entered($input, $output, $serverPool)
    {
        $serverPool->getServer()->willThrow('LdapTools\Exception\LdapConnectionException');
        $output->writeln(Argument::containingString('Cannot connect to LDAP server'))->shouldBeCalled();

        $this->execute($input, $output)->shouldBeEqualTo(1);
    }

    function it_should_output_the_config_at_the_end_if_specified($input, $output, $questionHelper)
    {
        $questionHelper->ask($input, $output, $this->askShowConfig)->willReturn(true);
        $expectedConfig = "ldap_tools:\n"
            ."    domains:\n"
            ."        foo.bar:\n"
            ."            domain_name: foo.bar\n"
            ."            base_dn: 'dc=foo,dc=bar'\n"
            ."            username: foo\n"
            ."            password: '12345'\n"
            ."            servers: [foo]\n"
            ."            use_tls: true\n";
        $output->writeln($expectedConfig)->shouldBeCalled();

        $this->execute($input, $output)->shouldBeEqualTo(0);
    }

    function it_should_not_output_the_config_at_the_end_if_not_specified($input, $output, $questionHelper)
    {
        $questionHelper->ask($input, $output, $this->askShowConfig)->willReturn(false);
        $output->writeln(Argument::containing('ldap_tools:'))->shouldNotBeCalled();

        $this->execute($input, $output)->shouldBeEqualTo(0);
    }

    function it_should_not_prompt_in_non_interactive_mode($input, $output, $questionHelper)
    {
        $input->getOption('server')->willReturn('foo');
        $input->getOption('username')->willReturn('foo');
        $input->getOption('password')->willReturn('12345');
        $input->getOption('non-interactive')->willReturn(true);

        $questionHelper->ask($input, $output, Argument::any())->shouldNotBeCalled();

        // Should not show a config
        $output->writeln(Argument::containingString('domain_name: foo.bar'))->shouldNotBeCalled();
        // Should output the status
        $output->writeln(Argument::containingString('Successfully authenticated'))->shouldBeCalled();

        $this->execute($input, $output)->shouldBeEqualTo(0);
    }

    function it_should_show_the_config_at_the_end_in_non_interactive_mode_if_specified($input, $output)
    {
        $input->getOption('server')->willReturn('foo');
        $input->getOption('username')->willReturn('foo');
        $input->getOption('password')->willReturn('12345');
        $input->getOption('non-interactive')->willReturn(true);
        $input->getOption('show-config')->willReturn(true);

        $output->writeln(Argument::containingString('ldap_tools:'))->shouldBeCalled();

        $this->execute($input, $output)->shouldBeEqualTo(0);
    }

    function it_should_show_only_the_config_at_the_end_in_non_interactive_mode_if_specified_with_silent($input, $output)
    {
        $input->getOption('server')->willReturn('foo');
        $input->getOption('username')->willReturn('foo');
        $input->getOption('password')->willReturn('12345');
        $input->getOption('non-interactive')->willReturn(true);
        $input->getOption('show-config')->willReturn(true);
        $input->getOption('silent')->willReturn(true);

        $output->writeln(Argument::containingString('Successfully authenticated'))->shouldNotBeCalled();
        $output->writeln(Argument::containingString('ldap_tools:'))->shouldBeCalled();

        $this->execute($input, $output)->shouldBeEqualTo(0);
    }
}
