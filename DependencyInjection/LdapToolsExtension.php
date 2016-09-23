<?php
/**
 * This file is part of the LdapToolsBundle package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace LdapTools\Bundle\LdapToolsBundle\DependencyInjection;

use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\Config\FileLocator;
use Symfony\Component\DependencyInjection\Reference;
use Symfony\Component\HttpKernel\DependencyInjection\Extension;
use Symfony\Component\DependencyInjection\Loader;

/**
 * Load and configure the needed services/parameters for the bundle.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class LdapToolsExtension extends Extension
{
    /**
     * {@inheritdoc}
     */
    public function load(array $configs, ContainerBuilder $container)
    {
        $configuration = new Configuration($container->getParameter('kernel.debug'));
        $config = $this->processConfiguration($configuration, $configs);

        $loader = new Loader\XmlFileLoader($container, new FileLocator(__DIR__.'/../Resources/config'));
        $loader->load('services.xml');

        $this->setLdapConfigDefinition($container, $config);
        $this->setSecurityConfiguration($container, $config['security']);
    }

    /**
     * Pass the configuration to be loaded for the LdapTools Configuration class.
     *
     * @param ContainerBuilder $container
     * @param array $config
     */
    protected function setLdapConfigDefinition(ContainerBuilder $container, array $config)
    {
        $ldapCfg = ['general' => $config['general']];

        // Only tag the cache warmer/doctrine event subscriber if there are domains listed in the config...
        if (isset($config['domains']) && !empty($config['domains'])) {
            $ldapCfg['domains'] = $config['domains'];
            $container->getDefinition('ldap_tools.cache_warmer.ldap_tools_cache_warmer')->addTag('kernel.cache_warmer');
            $container->getDefinition('ldap_tools.doctrine.event_listener.ldap_object')->addTag(
                'doctrine.event_subscriber',
                ['connection' => 'default']
            );
        } else {
            $container->getDefinition('data_collector.ldap_tools')->replaceArgument(0, null);
        }

        $definition = $container->getDefinition('ldap_tools.configuration');
        $definition->addMethodCall('loadFromArray', [$ldapCfg]);
        $definition->addMethodCall('setEventDispatcher', [new Reference('ldap_tools.event_dispatcher')]);

        $loggerChain = $container->getDefinition('ldap_tools.log.logger_chain');
        if ($config['logging']) {
            $loggerChain->addMethodCall('addLogger', [new Reference('ldap_tools.log.logger')]);
        }
        if ($config['profiling']) {
            $loggerChain->addMethodCall('addLogger', [new Reference('ldap_tools.log.profiler')]);
        }
        if ($config['logging'] || $config['profiling']) {
            $definition->addMethodCall('setLogger', [new Reference('ldap_tools.log.logger_chain')]);
        }
    }

    /**
     * @param ContainerBuilder $container
     * @param array $config
     */
    protected function setSecurityConfiguration(ContainerBuilder $container, array $config)
    {
        $roles = isset($config['roles']) ? $config['roles'] : [];
        $additionalAttributes = isset($config['additional_attributes']) ? $config['additional_attributes'] : [];

        $container->setParameter('ldap_tools.security.default_attributes', $config['default_attributes']);
        $container->setParameter('ldap_tools.security.additional_attributes', $additionalAttributes);
        $container->setParameter('ldap_tools.security.check_groups_recursively', $config['check_groups_recursively']);
        $container->setParameter('ldap_tools.security.user', $config['user']);
        $container->setParameter('ldap_tools.security.roles', $roles);
        $container->setParameter('ldap_tools.security.default_role', $config['default_role']);

        $container->getDefinition('ldap_tools.security.user.ldap_user_provider')->addMethodCall(
            'setLdapObjectType',
            [$config['ldap_object_type']]
        );

        $container->getDefinition('ldap_tools.security.ldap_guard_authenticator')->addMethodCall(
            'setStartPath',
            [$config['guard']['start_path']]
        );

        $userProviderDef = $container->getDefinition('ldap_tools.security.user.ldap_user_provider');
        if (isset($config['search_base'])) {
            $userProviderDef->addMethodCall(
                'setSearchBase',
                [$config['search_base']]
            );
        }
        $userProviderDef->addMethodCall(
            'setRoleLdapType',
            [$config['role_ldap_type']]
        );
        $userProviderDef->addMethodCall(
            'setRoleAttributeMap',
            [$config['role_attributes']]
        );
        $userProviderDef->addMethodCall(
            'setRefreshAttributes',
            [$config['refresh_user_attributes']]
        );
        $userProviderDef->addMethodCall(
            'setRefreshRoles',
            [$config['refresh_user_roles']]
        );
    }
}
