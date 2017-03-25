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
use Symfony\Component\DependencyInjection\ParameterBag\ParameterBagInterface;
use Symfony\Component\DependencyInjection\Reference;

class LdapToolsExtensionSpec extends ObjectBehavior
{
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
            'doctrine' => [
                'integration_enabled' => true,
                'connections' => [ null ],
            ],
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
                    'connect_timeout' => 5,
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

    function let(ContainerBuilder $container, ParameterBagInterface $parameterBag, Definition $configDef, Definition $loggerDef, Definition  $cacheWarmer, Definition $doctrineEvents, Definition $userProvider, Definition $guardDef, Definition $entryDef)
    {
        $container->getParameter('kernel.debug')->willReturn(false);

        // Do some needed setup so it loads resources correctly.
        // Without this (the hasExtension call) it will not parse the services file, making specs kinda difficult...
        $container->getParameterBag()->willReturn($parameterBag);
        $container->hasExtension('http://symfony.com/schema/dic/services')->willReturn(false);
        $container->addResource(Argument::type('\Symfony\Component\Config\Resource\ResourceInterface'))->willReturn(true);

        $container->getDefinition('ldap_tools.configuration')->willReturn($configDef);
        $container->getDefinition('ldap_tools.log.logger_chain')->willReturn($loggerDef);
        $container->getDefinition("ldap_tools.security.user.ldap_user_provider")->willReturn($userProvider);
        $container->getDefinition("ldap_tools.security.ldap_guard_authenticator")->willReturn($guardDef);
        $container->getDefinition('ldap_tools.security.authentication.form_entry_point')->willReturn($entryDef);
        $entryDef->addArgument(Argument::any())->willReturn($entryDef);

        $container->getDefinition("ldap_tools.cache_warmer.ldap_tools_cache_warmer")->willReturn($cacheWarmer);
        $container->getDefinition("ldap_tools.doctrine.event_listener.ldap_object")->willReturn($doctrineEvents);
    }

    function it_is_initializable()
    {
        $this->shouldHaveType('LdapTools\Bundle\LdapToolsBundle\DependencyInjection\LdapToolsExtension');
    }

    function it_should_load_the_configuration($container, $cacheWarmer, $doctrineEvents, $configDef, $guardDef, $userProvider, $entryDef)
    {
        // These are all the definitions that should be processed from the services resource file...
        $container->setDefinition('ldap_tools.configuration', Argument::type('Symfony\Component\DependencyInjection\Definition'))->shouldBeCalled();
        $container->setDefinition('ldap_tools.event_dispatcher', Argument::type('Symfony\Component\DependencyInjection\Definition'))->shouldBeCalled();
        $container->setDefinition('ldap_tools.ldap_manager', Argument::type('Symfony\Component\DependencyInjection\Definition'))->shouldBeCalled();
        $container->setDefinition('ldap_tools.log.logger_chain', Argument::type('Symfony\Component\DependencyInjection\Definition'))->shouldBeCalled();
        $container->setDefinition('ldap_tools.log.profiler', Argument::type('Symfony\Component\DependencyInjection\Definition'))->shouldBeCalled();
        $container->setDefinition('ldap_tools.log.logger', Argument::type('Symfony\Component\DependencyInjection\Definition'))->shouldBeCalled();
        $container->setDefinition('data_collector.ldap_tools', Argument::type('Symfony\Component\DependencyInjection\Definition'))->shouldBeCalled();
        $container->setDefinition('ldap_tools.security.user.ldap_user_checker', Argument::type('Symfony\Component\DependencyInjection\Definition'))->shouldBeCalled();
        $container->setDefinition('ldap_tools.security.firewall.ldap_form_login_listener', Argument::type('Symfony\Component\DependencyInjection\Definition'))->shouldBeCalled();
        $container->setDefinition('ldap_tools.security.user.ldap_user_provider', Argument::type('Symfony\Component\DependencyInjection\Definition'))->shouldBeCalled();
        $container->setDefinition('ldap_tools.security.authentication.ldap_authentication_provider', Argument::type('Symfony\Component\DependencyInjection\Definition'))->shouldBeCalled();
        $container->setDefinition('ldap_tools.cache_warmer.ldap_tools_cache_warmer', Argument::type('Symfony\Component\DependencyInjection\Definition'))->shouldBeCalled();
        $container->setDefinition('ldap_tools.form.type.ldap_object', Argument::type('Symfony\Component\DependencyInjection\Definition'))->shouldBeCalled();
        $container->setDefinition('ldap_tools.doctrine.event_listener.ldap_object', Argument::type('Symfony\Component\DependencyInjection\Definition'))->shouldBeCalled();
        $container->setDefinition('ldap_tools.security.ldap_guard_authenticator', Argument::type('Symfony\Component\DependencyInjection\Definition'))->shouldBeCalled();
        $container->setDefinition('ldap_tools.ldif_parser', Argument::type('Symfony\Component\DependencyInjection\Definition'))->shouldBeCalled();
        $container->setDefinition('ldap_tools.security.auth_success_handler', Argument::type('Symfony\Component\DependencyInjection\Definition'))->shouldBeCalled();
        $container->setDefinition('ldap_tools.security.auth_failure_handler', Argument::type('Symfony\Component\DependencyInjection\Definition'))->shouldBeCalled();
        $container->setDefinition("ldap_tools.security.authentication.form_entry_point", Argument::type('Symfony\Component\DependencyInjection\Definition'))->shouldBeCalled();
        // Sets these by default when a domain is defined...
        $cacheWarmer->addTag("kernel.cache_warmer")->shouldBeCalled();
        $doctrineEvents->addTag("doctrine.event_subscriber")->shouldBeCalled();

        // Expected parameter settings...
        $container->setParameter('ldap_tools.security.additional_attributes', [])->shouldBeCalled();
        $container->setParameter('ldap_tools.security.check_groups_recursively', true)->shouldBeCalled();
        $container->setParameter('ldap_tools.security.user', '\LdapTools\Bundle\LdapToolsBundle\Security\User\LdapUser')->shouldBeCalled();
        $container->setParameter('ldap_tools.security.roles', [])->shouldBeCalled();
        $container->setParameter('ldap_tools.security.default_role', 'ROLE_USER')->shouldBeCalled();

        $container->setParameter("ldap_tools.security.guard.auth_success", [
            "default_target_path" => "/",
            "always_use_target_path" => false,
            "target_path_parameter" => "_target_path",
            "use_referrer" => false,
            "login_path" => '/login',
        ])->shouldBeCalled();
        $container->setParameter("ldap_tools.security.guard.auth_failure", [
            "failure_path" => null,
            "failure_forward" => false,
            "failure_path_parameter" => "_failure_path",
            "login_path" => '/login',
        ])->shouldBeCalled();
        $container->setParameter("ldap_tools.security.guard.options", [
            "username_parameter" => "_username",
            "password_parameter" => "_password",
            "domain_parameter" => "_ldap_domain"
        ])->shouldBeCalled();

        $configDef->addMethodCall('loadFromArray', Argument::any())->shouldBeCalled();
        $configDef->addMethodCall('setEventDispatcher', [new Reference('ldap_tools.event_dispatcher')])->shouldBeCalled();

        $entryDef->addArgument(new Reference('security.http_utils'))->shouldBeCalled()->willReturn($entryDef);
        $entryDef->addArgument('/login')->shouldBeCalled()->willReturn($entryDef);
        $entryDef->addArgument(false)->shouldBeCalled()->willReturn($entryDef);

        $userProvider->addMethodCall('setLdapObjectType', [LdapObjectType::USER])->shouldBeCalled();
        $userProvider->addMethodCall('setRoleLdapType', [LdapObjectType::GROUP])->shouldBeCalled();
        $userProvider->addMethodCall('setRefreshAttributes', [false])->shouldBeCalled();
        $userProvider->addMethodCall('setRefreshRoles', [false])->shouldBeCalled();
        $userProvider->addMethodCall('setRoleAttributeMap', [["name" => "name", "sid" => "sid", "guid" => "guid", "members" => "members"]])->shouldBeCalled();

        $this->load($this->config, $container);
    }

    function it_should_set_the_profiler_and_logger_when_the_kernel_is_in_debug_mode($container, $loggerDef)
    {
        $container->setDefinition(Argument::any(), Argument::any())->shouldBeCalled();
        $container->setParameter(Argument::any(), Argument::any())->shouldBeCalled();

        $container->getParameter('kernel.debug')->willReturn(true);
        $loggerDef->addMethodCall('addLogger', [new Reference('ldap_tools.log.logger')])->shouldBeCalled();
        $loggerDef->addMethodCall('addLogger', [new Reference('ldap_tools.log.profiler')])->shouldBeCalled();

        $this->load($this->config, $container);
    }

    function it_should_set_security_settings_specified_in_the_config($container, $userProvider)
    {
        $container->setDefinition(Argument::any(), Argument::any())->shouldBeCalled();
        $container->setParameter(Argument::any(), Argument::any())->shouldBeCalled();

        $roles = ['ROLE_FOO' => ['foo']];
        $config = $this->config;
        $config['ldap_tools']['security']['roles'] = $roles;
        $config['ldap_tools']['security']['ldap_object_type'] = 'foo';
        $config['ldap_tools']['security']['default_role'] = 'ROLE_FOOBAR';
        $config['ldap_tools']['security']['user'] = '\foo';
        $config['ldap_tools']['security']['additional_attributes'] = ['foo', 'bar'];
        $config['ldap_tools']['security']['check_groups_recursively'] = false;
        $config['ldap_tools']['security']['search_base'] = 'ou=foo,dc=example,dc=local';
        $config['ldap_tools']['security']['role_ldap_type'] = 'foo';
        $config['ldap_tools']['security']['role_attributes'] = ['members' => 'foo'];
        $config['ldap_tools']['security']['refresh_user_attributes'] = false;
        $config['ldap_tools']['security']['refresh_user_roles'] = false;

        $container->setParameter('ldap_tools.security.roles', $roles)->shouldBeCalled();
        $container->setParameter('ldap_tools.security.default_role', 'ROLE_FOOBAR')->shouldBeCalled();
        $container->setParameter('ldap_tools.security.user', '\foo')->shouldBeCalled();
        $container->setParameter('ldap_tools.security.additional_attributes', ['foo','bar'])->shouldBeCalled();
        $container->setParameter('ldap_tools.security.check_groups_recursively', false)->shouldBeCalled();
        $userProvider->addMethodCall('setLdapObjectType', ['foo'])->shouldBeCalled();
        $userProvider->addMethodCall('setSearchBase', ['ou=foo,dc=example,dc=local'])->shouldBeCalled();
        $userProvider->addMethodCall('setRoleLdapType', ['foo'])->shouldBeCalled();
        $userProvider->addMethodCall('setRefreshAttributes', [false])->shouldBeCalled();
        $userProvider->addMethodCall('setRefreshRoles', [false])->shouldBeCalled();
        $userProvider->addMethodCall('setRoleAttributeMap', [["members" => "foo", "name" => "name", "sid" => "sid", "guid" => "guid"]])->shouldBeCalled();
        
        $this->load($config, $container);
    }

    function it_should_not_add_the_cache_warmer_or_doctrine_event_tags_if_no_domains_are_defined($doctrineEvents, $cacheWarmer, $container, Definition $def)
    {
        $config = $this->config;
        unset($config['ldap_tools']['domains']);

        $container->setDefinition(Argument::any(), Argument::any())->willReturn($def);
        $container->getDefinition(Argument::any())->willReturn($def);
        $container->setParameter(Argument::any(), Argument::any())->willReturn($def);

        // Should not be set when there are no domains...
        $cacheWarmer->addTag(Argument::any())->shouldNotBeCalled();
        $doctrineEvents->addTag(Argument::any(), Argument::any())->shouldNotBeCalled();

        $this->load($config, $container);
    }

    function it_should_not_add_the_doctrine_event_subscriber_if_it_is_set_to_be_disabled($doctrineEvents, $container, Definition $def)
    {
        $config = $this->config;
        $config['ldap_tools']['doctrine']['integration_enabled'] = false;

        $container->setDefinition(Argument::any(), Argument::any())->willReturn($def);
        $container->getDefinition(Argument::any())->willReturn($def);
        $container->setParameter(Argument::any(), Argument::any())->willReturn($def);

        $doctrineEvents->addTag(Argument::any(), Argument::any())->shouldNotBeCalled();

        $this->load($config, $container);
    }

    function it_should_integrate_with_only_specific_doctrine_connections_if_specified($doctrineEvents, $container, Definition $def)
    {
        $config = $this->config;
        $config['ldap_tools']['doctrine']['connections'] = ['foo', 'bar'];

        $container->setDefinition(Argument::any(), Argument::any())->willReturn($def);
        $container->getDefinition(Argument::any())->willReturn($def);
        $container->setParameter(Argument::any(), Argument::any())->willReturn($def);

        $doctrineEvents->addTag("doctrine.event_subscriber", ['connection' => 'foo'])->shouldBeCalled();
        $doctrineEvents->addTag("doctrine.event_subscriber", ['connection' => 'bar'])->shouldBeCalled();

        $this->load($config, $container);
    }
}
