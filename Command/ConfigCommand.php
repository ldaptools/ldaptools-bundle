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

use LdapTools\Bundle\LdapToolsBundle\Factory\LdapFactory;
use LdapTools\Connection\LdapConnection;
use LdapTools\Connection\LdapServerPool;
use LdapTools\DomainConfiguration;
use LdapTools\Exception\LdapConnectionException;
use LdapTools\Operation\AuthenticationOperation;
use LdapTools\Operation\AuthenticationResponse;
use LdapTools\Utilities\LdapUtilities;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Helper\QuestionHelper;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Question\ChoiceQuestion;
use Symfony\Component\Console\Question\ConfirmationQuestion;
use Symfony\Component\Console\Question\Question;
use Symfony\Component\Yaml\Yaml;

/**
 * Assists in generating the LdapTools configuration for the bundle.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class ConfigCommand extends Command
{
    /**
     * @var OutputInterface
     */
    protected $output;

    /**
     * @var InputInterface
     */
    protected $input;

    /**
     * @var QuestionHelper
     */
    protected $helper;

    /**
     * @var bool
     */
    protected $silent = false;

    /**
     * @var bool
     */
    protected $interactive = true;

    /**
     * @var LdapServerPool
     */
    protected $serverPool;

    /**
     * @var LdapFactory
     */
    protected $factory;

    /**
     * @param null|string $name
     */
    public function __construct($name = null)
    {
        $this->factory = new LdapFactory();
        parent::__construct($name);
    }

    /**
     * @param LdapServerPool $serverPool
     */
    public function setLdapServerPool(LdapServerPool $serverPool)
    {
        $this->serverPool = $serverPool;
    }

    /**
     * @param LdapFactory $factory
     */
    public function setConnectionFactory(LdapFactory $factory)
    {
        $this->factory = $factory;
    }

    /**
     * {@inheritDoc}
     */
    protected function configure()
    {
        $this
            ->setName('ldaptools:generate:config')
            ->addOption('domain', null, InputOption::VALUE_OPTIONAL, 'The LDAP domain name (ie. domain.local).')
            ->addOption('username', null, InputOption::VALUE_OPTIONAL, 'The LDAP username.')
            ->addOption('password', null, InputOption::VALUE_OPTIONAL, 'The LDAP password.')
            ->addOption('server', null, InputOption::VALUE_OPTIONAL | InputOption::VALUE_IS_ARRAY, 'The LDAP server to use.')
            ->addOption('port', null, InputOption::VALUE_OPTIONAL, 'The LDAP server port to use.', 389)
            ->addOption('use-tls', null, InputOption::VALUE_NONE, 'Whether or not TLS should be used for the connection.')
            ->addOption('use-ssl', null, InputOption::VALUE_NONE, 'Whether or not to use SSL (TLS over port 636).')
            ->addOption('silent', null, InputOption::VALUE_NONE, 'Only the YAML config will be displayed.')
            ->addOption('non-interactive', null, InputOption::VALUE_NONE, 'No prompts or questions. Requires: server/domain, username, password')
            ->addOption('show-config', null, InputOption::VALUE_NONE, 'Show the config at the end without prompting.')
            ->setDescription('Assists in generating the base LDAP YAML configuration needed for the bundle.');
    }

    /**
     * {@inheritdoc}
     */
    public function execute(InputInterface $input, OutputInterface $output)
    {
        $config = null;
        $connection = null;

        $this->input = $input;
        $this->output = $output;
        $this->helper = $this->getHelper('question');
        $this->silent = $input->getOption('silent');
        $this->interactive = !$input->getOption('non-interactive');
        $this->serverPool = $this->serverPool ?: new LdapServerPool(new DomainConfiguration(''));

        $domain = trim($input->getOption('domain'));
        $server = $input->getOption('server');
        $port = (int) $input->getOption('port');
        $username = trim($input->getOption('username'));
        $password = $input->getOption('password');
        $useTls = $input->getOption('use-tls');
        $useSsl = $input->getOption('use-ssl');
        $this->validateOptions($server, $domain, $username, $password, $useTls, $useSsl);

        while (!$connection) {
            $config = $this->getConfigForDomain($server, $domain, $port, $useTls, $useSsl);
            if (!$config && (!$this->interactive || !$this->confirm('<question>Try again? [Y/n]: </question>'))) {
                return 1;
            } elseif (!$config) {
                continue;
            }
            $connection = $this->getLdapConnection($config);
            if (!$connection && (!$this->interactive || !$this->confirm('<question>Try again? [Y/n]: </question>'))) {
                return 1;
            }
        }
        if (!$useTls && !$useSsl && $this->interactive) {
            while (!$this->chooseEncryption($connection)) {
                if ($this->confirm('<question>Continue without encryption? [Y/n]: </question>')) {
                    break;
                }
            }
        }

        while (!$this->verifyCredentials($connection, $username, $password)) {
            if (!$this->confirm('<question>Try a different username/password? [Y/n]: </question>')) {
                return 1;
            }
            $username = null;
            $password = null;
        }

        $this->askAndShowConfig($config, $input, $output);

        return 0;
    }

    /**
     * @param string $server
     * @param string $domain
     * @param string $username
     * @param string $password
     * @param bool $useTls
     * @param bool $useSsl
     */
    protected function validateOptions($server, $domain, $username, $password, $useTls, $useSsl)
    {
        if ($useTls && $useSsl) {
            throw new \LogicException('You cannot use both the ssl and tls option. Generally you want --use-tls.');
        }
        if (!$this->interactive && !$server && !$domain) {
            throw new \LogicException('You must enter a server or domain when not in interactive mode.');
        }
        if (!$this->interactive && (!$username || !$password)) {
            throw new \LogicException('You must enter a username and password when not in interactive mode.');
        }
    }

    /**
     * @param string|null $server
     * @param string|null $domain
     * @param int|null $port
     * @param bool $useTls
     * @param bool $useSsl
     * @return DomainConfiguration|null
     */
    protected function getConfigForDomain($server, $domain, $port, $useTls, $useSsl)
    {
        $config = ($this->factory->getConfig($domain))
            ->setLazyBind(true)
            ->setUseTls($useTls)
            ->setUseSsl($useSsl);
        $config = $this->setServerOrDomain($config, $server, $domain);
        if ($port) {
            $config->setPort($port);
        }
        $this->serverPool->setConfig($config);

        try {
            $config->setServers([$this->serverPool->getServer()]);
        } catch (LdapConnectionException $e) {
            if (!empty($config->getServers())) {
                $this->writeln(sprintf('<error>Cannot connect to LDAP server %s on port %s.</error>', $config->getServers()[0], $config->getPort()));
            } else {
                $this->writeln(sprintf('<error>Cannot find any LDAP severs for domain: %s</error>', $domain));
            }

            return null;
        }
        $this->writeln(sprintf('<info>Server %s is responding on port %s.</info>', $config->getServers()[0], $config->getPort()));

        return $config;
    }

    /**
     * @param DomainConfiguration $config
     * @param string|null $server
     * @param string|null $domain
     * @return DomainConfiguration|null
     */
    protected function setServerOrDomain(DomainConfiguration $config, $server, $domain)
    {
        while (!$domain && !$server) {
            if (!$server && $this->interactive) {
                $defaultServer = $this->getDefaultServerName();
                $server = $this->promptForResponse(
                    'Enter a server name '
                    . ($defaultServer ? "[$defaultServer]" : '(Leave empty to attempt lookup via domain name)') . ': ',
                    $defaultServer
                );
            }
            if (!$server && !$domain && $this->interactive) {
                $defaultDomain = $this->getDefaultDomainName();
                $domain = $this->promptForResponse('Enter a domain name' . ($defaultDomain ? " [$defaultDomain]" : '') . ': ', $defaultDomain);
            }
            if (!$domain && !$server) {
                $this->writeln('<error>You must enter a domain name or server name.</error>');
                if (!$this->interactive) {
                    return null;
                }
            }
        }

        if ($server) {
            $config->setServers(is_array($server) ? $server : [$server]);
        }
        if ($domain) {
            $config->setDomainName($domain);
        }

        return $config;
    }

    /**
     * @param DomainConfiguration $config
     * @return LdapConnection|null
     */
    protected function getLdapConnection(DomainConfiguration $config)
    {
        $connection = $this->factory->getConnection($config);

        try {
            $rootDse = $connection->getRootDse();
        } catch (\Exception $e) {
            $this->writeln(sprintf(
                '<error>Unable to query the RootDSE. %s</error>',
                $e->getMessage()
            ));

            return null;
        }

        $baseDn = null;
        if ($rootDse->has('defaultNamingContext')) {
            $baseDn = $rootDse->get('defaultNamingContext');
        } else {
            $contexts = $rootDse->get('namingContexts');
            $baseDn = is_array($contexts) ? $contexts[0] : $contexts;
        }
        $config->setBaseDn($baseDn)->setDomainName(implode('.', LdapUtilities::explodeDn($baseDn)));
        $this->writeln(sprintf('<info>Successfully connected to: %s</info>', $config->getDomainName()));

        return $connection;
    }

    /**
     * @param LdapConnection $connection
     * @param string|null $username
     * @param string|null $password
     * @return bool
     */
    protected function verifyCredentials(LdapConnection $connection, $username, $password)
    {
        if (!$username && $this->interactive) {
            $defaultUser = $this->getDefaultUsername();
            $username = $this->promptForResponse('Enter the LDAP username' . ($defaultUser ? " [$defaultUser]" : '') . ': ', $defaultUser, false, function ($value) {
                if (trim($value) === '') {
                    throw new \Exception('The username cannot be empty.');
                }

                return $value;
            });
        }

        $validatePassword = function ($value) {
            if (empty($value)) {
                throw new \InvalidArgumentException('The password cannot be empty.');
            }

            return $value;
        };
        while (!$password && $this->interactive) {
            $original = $this->promptForResponse(sprintf('Enter the LDAP password for %s: ', $username), null, true, $validatePassword);
            $verified = $this->promptForResponse('Enter the password again to confirm: ', null, true, $validatePassword);
            if ($original !== $verified) {
                $this->writeln('<error>Passwords do not match. Please enter them again.</error>');
            } else {
                $password = $verified;
            }
        }
        /** @var AuthenticationResponse $response */
        $response = $connection->execute(new AuthenticationOperation($username, $password));

        if ($response->isAuthenticated()) {
            $this->writeln(sprintf('<info>Successfully authenticated with user: %s</info>', $username));
            $connection->getConfig()->setUsername($username)->setPassword($password);

            return true;
        }
        $this->writeln(sprintf('<error>Unable to authenticate to LDAP: %s</error>', $response->getErrorMessage()));

        return false;
    }

    /**
     * @param LdapConnection $connection
     * @return bool
     */
    protected function chooseEncryption(LdapConnection $connection)
    {
        $question = new ChoiceQuestion(
            'Encryption is currently not enabled for this connection. Please make a selection [TLS]: ',
            ['TLS', 'SSL', 'None'],
            '0'
        );
        $answer = $this->helper->ask($this->input, $this->output, $question);

        if ($answer === 'None') {
            return true;
        }
        $useSsl = $connection->getConfig()->getUseSsl();
        $useTls = $connection->getConfig()->getUseTls();

        if ($answer === 'TLS') {
            $connection->getConfig()->setUseTls(true);
        } else {
            $connection->getConfig()->setUseSsl(true);
        }

        $success = false;
        try {
            // RootDSE is cached in the connection initially. Make sure to use a new connection...
            $success = (bool) $this->factory->getConnection($connection->getConfig())->getRootDse();
            $this->writeln(sprintf('<info>Connected to LDAP via %s.</info>', $answer));
        } catch (\Exception $e) {
            $this->writeln(sprintf('<error>Error connecting via %s. %s</error>', $answer, $e->getMessage()));
        } finally {
            if (!$success) {
                $connection->getConfig()->setUseSsl($useSsl);
                $connection->getConfig()->setUseTls($useTls);
            }
        }

        return $success;
    }

    protected function askAndShowConfig(DomainConfiguration $config, InputInterface $input, OutputInterface $output)
    {
        if ($input->getOption('show-config') || $this->confirm('<question>Show the generated config (includes password)? [Y/n]: </question>')) {
            $this->writeln('');
            $output->writeln(Yaml::dump($this->getYamlArrayFromConfig($config), 4));
        }
    }

    /**
     * @param DomainConfiguration $config
     * @return array
     */
    protected function getAllLdapServersForDomain(DomainConfiguration $config)
    {
        $server = strtolower($config->getServers()[0]);
        // Slice the array to 5, as it's possible for a large amount of LDAP servers...
        $servers = array_map('strtolower', array_slice(
            LdapUtilities::getLdapServersForDomain($config->getDomainName()),
            0,
            5
        ));

        // We want to make sure to pop the tested server to the front...
        $pos = array_search($server, $servers);
        if ($pos !== false) {
            unset($servers[$pos]);
        }
        // But if we have a FQDN version, prefer that...
        $pos = array_search($server.'.'.strtolower($config->getDomainName()), $servers);
        if ($pos !== false) {
            unset($servers[$pos]);
            $server .= '.'.$config->getDomainName();
        }
        array_unshift($servers, $server);

        return $servers;
    }

    /**
     * @return string|null
     */
    protected function getDefaultDomainName()
    {
        return isset($_SERVER['USERDNSDOMAIN']) ? $_SERVER['USERDNSDOMAIN'] : null;
    }

    /**
     * @return string|null
     */
    protected function getDefaultServerName()
    {
        return isset($_SERVER['LOGONSERVER']) ? ltrim($_SERVER['LOGONSERVER'], '\\') : null;
    }

    /**
     * @return string|null
     */
    protected function getDefaultUsername()
    {
        $user = null;

        if (isset($_SERVER['USERNAME'])) {
            $user = $_SERVER['USERNAME'];
        } elseif ($_SERVER['USER']) {
            $user = $_SERVER['USER'];
        }

        return $user;
    }

    /**
     * @param DomainConfiguration $config
     * @return array
     */
    protected function getYamlArrayFromConfig(DomainConfiguration $config)
    {
        $domainCfg = [
            'domain_name' => $config->getDomainName(),
            'base_dn' => $config->getBaseDn(),
            'username' => $config->getUsername(),
            'password' => $config->getPassword(),
            'servers' => $this->getAllLdapServersForDomain($config),
        ];
        if ($config->getPort() !== 389) {
            $domainCfg['port'] = $config->getPort();
        }
        if ($config->getUseTls()) {
            $domainCfg['use_tls'] = true;
        }
        if ($config->getUseSsl()) {
            $domainCfg['use_ssl'] = true;
        }

        return [
            'ldap_tools' => [
                'domains' => [
                    $config->getDomainName() => $domainCfg
                ]
            ]
        ];
    }

    /**
     * @param string $message
     * @param bool $default
     * @return bool
     */
    protected function confirm($message, $default = true)
    {
        if (!$this->interactive) {
            return false;
        }

        return $this->helper->ask($this->input, $this->output, new ConfirmationQuestion($message, $default));
    }

    /**
     * @param string $message
     * @param null|string $default
     * @param bool $hide
     * @param null|callable $validator
     * @return string
     */
    protected function promptForResponse($message, $default = null, $hide = false, $validator = null)
    {
        $question =  (new Question($message, $default))->setHidden($hide);
        if ($validator) {
            $question->setValidator($validator);
        }

        return $this->helper->ask($this->input, $this->output, $question);
    }

    /**
     * @param $message
     */
    protected function writeln($message)
    {
        if (!$this->silent) {
            $this->output->writeln($message);
        }
    }
}
