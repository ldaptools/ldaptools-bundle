<?php
/**
 * This file is part of the LdapToolsBundle package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace spec\LdapTools\Bundle\LdapToolsBundle\DependencyInjection;

use LdapTools\Object\LdapObjectType;
use PhpSpec\ObjectBehavior;
use Prophecy\Argument;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;
use Symfony\Component\DependencyInjection\Reference;

class LdapToolsExtensionSpec extends ObjectBehavior
{
    /**
     * @var ContainerBuilder
     */
    protected $container;

    /**
     * @var Definition
     */
    protected $loggerDef;

    /**
     * @var Definition
     */
    protected $configDef;

    /**
     * @var Definition
     */
    protected $cacheWarmer;

    /**
     * @var Definition
     */
    protected $doctrineEvents;

    /**
     * @var Definition
     */
    protected $userProvider;

    /**
     * @var Definition
     */
    protected $guardDef;
    
    /**
     * @var array
     */
    protected $attrMap = [
        "username" => "username",
        "accountNonLocked" => "locked",
        "accountNonExpired" => "accountExpirationDate",
        "enabled" => "disabled",
        "credentialsNonExpired" => "passwordMustChange",
        "groups" => "groups",
        "guid" => "guid",
        "stringRepresentation" => "username",
    ];

    /**
     * @var array
     */
    protected $config = [
        'ldap_tools' => [
            'general' => [
                'default_domain' => 'foo.bar',
            ],
            'domains' => [
                'example.local' => [
                    'domain_name' => 'example.local',
                    'schema_name' => 'foo',
                    'servers' => ['foo'],
                    'username' => 'foo',
                    'password' => 'bar',
                    'use_paging' => false,
                    'use_tls' => false,
                    'use_ssl' => false,
                    'ldap_type' => 'ad',
                    'base_dn' => 'dc=foo,dc=bar',
                    'port' => 2,
                    'lazy_bind' => false,
                    'server_selection' => 'random',
                    'encoding' => 'utf-8',
                    'bind_format' => '%username%,dc=foo,dc=bar',
                    'page_size' => 500,
                    'idle_reconnect' => 300,
                    'ldap_options' => [
                        'ldap_opt_protocol_version' => 3,
                    ],
                ],
                'foo.bar' => [
                    'domain_name' => 'foo.bar',
                    'servers' => ['bar'],
                    'username' => 'foobar',
                    'password' => '12345',
                ],
            ],
        ],
    ];

    /**
     * @param \Symfony\Component\DependencyInjection\ContainerBuilder $container
     * @param \Symfony\Component\DependencyInjection\ParameterBag\ParameterBagInterface $parameterBag
     * @param \Symfony\Component\DependencyInjection\Definition $configDef
     * @param \Symfony\Component\DependencyInjection\Definition $loggerDef
     * @param \Symfony\Component\DependencyInjection\Definition $cacheWarmer
     * @param \Symfony\Component\DependencyInjection\Definition $doctrineEvents
     * @param \Symfony\Component\DependencyInjection\Definition $userProvider
     * @param \Symfony\Component\DependencyInjection\Definition $guardDef
     */
    function let($container, $parameterBag, $configDef, $loggerDef, $cacheWarmer, $doctrineEvents, $userProvider, $guardDef)
    {
        $this->container = $container;
        $this->loggerDef = $loggerDef;
        $this->configDef = $configDef;
        $this->cacheWarmer = $cacheWarmer;
        $this->doctrineEvents = $doctrineEvents;
        $this->userProvider = $userProvider;
        $this->guardDef = $guardDef;
        $this->container->getParameter('kernel.debug')->willReturn(false);

        // Do some needed setup so it loads resources correctly.
        // Without this (the hasExtension call) it will not parse the services file, making specs kinda difficult...
        $this->container->getParameterBag()->willReturn($parameterBag);
        $this->container->hasExtension('http://symfony.com/schema/dic/services')->willReturn(false);
        $this->container->addResource(Argument::type('\Symfony\Component\Config\Resource\ResourceInterface'))->willReturn(true);

        $this->container->getDefinition('ldap_tools.configuration')->willReturn($this->configDef);
        $this->container->getDefinition('ldap_tools.log.logger_chain')->willReturn($this->loggerDef);
        $this->container->getDefinition("ldap_tools.security.user.ldap_user_provider")->willReturn($this->userProvider);
        $this->container->getDefinition("ldap_tools.security.ldap_guard_authenticator")->willReturn($this->guardDef);

        $this->container->getDefinition("ldap_tools.cache_warmer.ldap_tools_cache_warmer")->willReturn($this->cacheWarmer);
        $this->container->getDefinition("ldap_tools.doctrine.event_listener.ldap_object")->willReturn($this->doctrineEvents);

    }

    function it_is_initializable()
    {
        $this->shouldHaveType('LdapTools\Bundle\LdapToolsBundle\DependencyInjection\LdapToolsExtension');
    }

    function it_should_load_the_configuration()
    {
        // These are all the definitions that should be processed from the services resource file...
        $this->container->setDefinition('ldap_tools.configuration', Argument::type('Symfony\Component\DependencyInjection\Definition'))->shouldBeCalled();
        $this->container->setDefinition('ldap_tools.event_dispatcher', Argument::type('Symfony\Component\DependencyInjection\Definition'))->shouldBeCalled();
        $this->container->setDefinition('ldap_tools.ldap_manager', Argument::type('Symfony\Component\DependencyInjection\Definition'))->shouldBeCalled();
        $this->container->setDefinition('ldap_tools.log.logger_chain', Argument::type('Symfony\Component\DependencyInjection\Definition'))->shouldBeCalled();
        $this->container->setDefinition('ldap_tools.log.profiler', Argument::type('Symfony\Component\DependencyInjection\Definition'))->shouldBeCalled();
        $this->container->setDefinition('ldap_tools.log.logger', Argument::type('Symfony\Component\DependencyInjection\Definition'))->shouldBeCalled();
        $this->container->setDefinition('data_collector.ldap_tools', Argument::type('Symfony\Component\DependencyInjection\Definition'))->shouldBeCalled();
        $this->container->setDefinition('ldap_tools.security.user.ldap_user_checker', Argument::type('Symfony\Component\DependencyInjection\Definition'))->shouldBeCalled();
        $this->container->setDefinition('ldap_tools.security.firewall.ldap_form_login_listener', Argument::type('Symfony\Component\DependencyInjection\Definition'))->shouldBeCalled();
        $this->container->setDefinition('ldap_tools.security.user.ldap_user_provider', Argument::type('Symfony\Component\DependencyInjection\Definition'))->shouldBeCalled();
        $this->container->setDefinition('ldap_tools.security.authentication.ldap_authentication_provider', Argument::type('Symfony\Component\DependencyInjection\Definition'))->shouldBeCalled();
        $this->container->setDefinition('ldap_tools.cache_warmer.ldap_tools_cache_warmer', Argument::type('Symfony\Component\DependencyInjection\Definition'))->shouldBeCalled();
        $this->container->setDefinition('ldap_tools.form.type.ldap_object', Argument::type('Symfony\Component\DependencyInjection\Definition'))->shouldBeCalled();
        $this->container->setDefinition('ldap_tools.doctrine.event_listener.ldap_object', Argument::type('Symfony\Component\DependencyInjection\Definition'))->shouldBeCalled();
        $this->container->setDefinition('ldap_tools.security.ldap_guard_authenticator', Argument::type('Symfony\Component\DependencyInjection\Definition'))->shouldBeCalled();

        // Sets these by default when a domain is defined...
        $this->cacheWarmer->addTag("kernel.cache_warmer")->shouldBeCalled();
        $this->doctrineEvents->addTag("doctrine.event_subscriber", ["connection" => "default"])->shouldBeCalled();

        // Expected parameter settings...
        $this->container->setParameter('ldap_tools.security.default_attributes', $this->attrMap)->shouldBeCalled();
        $this->container->setParameter('ldap_tools.security.additional_attributes', [])->shouldBeCalled();
        $this->container->setParameter('ldap_tools.security.check_groups_recursively', true)->shouldBeCalled();
        $this->container->setParameter('ldap_tools.security.user', '\LdapTools\Bundle\LdapToolsBundle\Security\User\LdapUser')->shouldBeCalled();
        $this->container->setParameter('ldap_tools.security.roles', [])->shouldBeCalled();
        $this->container->setParameter('ldap_tools.security.default_role', 'ROLE_USER')->shouldBeCalled();

        $this->configDef->addMethodCall('loadFromArray', Argument::any())->shouldBeCalled();
        $this->configDef->addMethodCall('setEventDispatcher', [new Reference('ldap_tools.event_dispatcher')])->shouldBeCalled();
        $this->guardDef->addMethodCall('setStartPath', ["login"])->shouldBeCalled();

        $this->userProvider->addMethodCall('setLdapObjectType', [LdapObjectType::USER])->shouldBeCalled();
        $this->userProvider->addMethodCall('setRoleLdapType', [LdapObjectType::GROUP])->shouldBeCalled();
        $this->userProvider->addMethodCall('setRoleAttributeMap', [["name" => "name", "sid" => "sid", "guid" => "guid", "members" => "members"]])->shouldBeCalled();

        $this->load($this->config, $this->container);
    }

    function it_should_set_the_profiler_and_logger_when_the_kernel_is_in_debug_mode()
    {
        $this->container->setDefinition(Argument::any(), Argument::any())->shouldBeCalled();
        $this->container->setParameter(Argument::any(), Argument::any())->shouldBeCalled();

        $this->container->getParameter('kernel.debug')->willReturn(true);
        $this->loggerDef->addMethodCall('addLogger', [new Reference('ldap_tools.log.logger')])->shouldBeCalled();
        $this->loggerDef->addMethodCall('addLogger', [new Reference('ldap_tools.log.profiler')])->shouldBeCalled();

        $this->load($this->config, $this->container);
    }

    function it_should_set_security_settings_specified_in_the_config()
    {
        $this->container->setDefinition(Argument::any(), Argument::any())->shouldBeCalled();
        $this->container->setParameter(Argument::any(), Argument::any())->shouldBeCalled();

        $attr = $this->attrMap;
        $attr['username'] = 'upn';
        $roles = ['ROLE_FOO' => ['foo']];
        $config = $this->config;
        $config['ldap_tools']['security']['roles'] = $roles;
        $config['ldap_tools']['security']['ldap_object_type'] = 'foo';
        $config['ldap_tools']['security']['default_role'] = 'ROLE_FOOBAR';
        $config['ldap_tools']['security']['user'] = '\foo';
        $config['ldap_tools']['security']['additional_attributes'] = ['foo', 'bar'];
        $config['ldap_tools']['security']['default_attributes']['username'] = 'upn';
        $config['ldap_tools']['security']['check_groups_recursively'] = false;
        $config['ldap_tools']['security']['search_base'] = 'ou=foo,dc=example,dc=local';
        $config['ldap_tools']['security']['role_ldap_type'] = 'foo';
        $config['ldap_tools']['security']['role_attributes'] = ['members' => 'foo'];

        $this->container->setParameter('ldap_tools.security.roles', $roles)->shouldBeCalled();
        $this->container->setParameter('ldap_tools.security.default_role', 'ROLE_FOOBAR')->shouldBeCalled();
        $this->container->setParameter('ldap_tools.security.user', '\foo')->shouldBeCalled();
        $this->container->setParameter('ldap_tools.security.additional_attributes', ['foo','bar'])->shouldBeCalled();
        $this->container->setParameter('ldap_tools.security.default_attributes', $attr)->shouldBeCalled();
        $this->container->setParameter('ldap_tools.security.check_groups_recursively', false)->shouldBeCalled();
        $this->userProvider->addMethodCall('setLdapObjectType', ['foo'])->shouldBeCalled();
        $this->userProvider->addMethodCall('setSearchBase', ['ou=foo,dc=example,dc=local'])->shouldBeCalled();
        $this->userProvider->addMethodCall('setRoleLdapType', ['foo'])->shouldBeCalled();
        $this->userProvider->addMethodCall('setRoleAttributeMap', [["members" => "foo", "name" => "name", "sid" => "sid", "guid" => "guid"]])->shouldBeCalled();
        
        $this->load($config, $this->container);
    }

    /**
     * @param \Symfony\Component\DependencyInjection\Definition $def
     */
    function it_should_not_add_the_cache_warmer_or_doctrine_event_tags_if_no_domains_are_defined($def)
    {
        $config = $this->config;
        unset($config['ldap_tools']['domains']);

        $this->container->setDefinition(Argument::any(), Argument::any())->willReturn($def);
        $this->container->getDefinition(Argument::any())->willReturn($def);
        $this->container->setParameter(Argument::any(), Argument::any())->willReturn($def);

        // Should not be set when there are no domains...
        $this->cacheWarmer->addTag(Argument::any())->shouldNotBeCalled();
        $this->doctrineEvents->addTag(Argument::any(), Argument::any())->shouldNotBeCalled();

        $this->load($config, $this->container);
    }
}
