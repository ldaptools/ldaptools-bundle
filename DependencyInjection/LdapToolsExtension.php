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
        $this->setDoctrineConfiguration($container, $config);
        $this->setSecurityConfiguration($container, $config['security']);
        $this->setGuardConfiguration($container, $config['security']['guard']);
    }

    /**
     * @param ContainerBuilder $container
     * @param array $config
     */
    protected function setDoctrineConfiguration(ContainerBuilder $container, array $config)
    {
        // If they explicitly disabled doctrine integration, do nothing...
        if (!$config['doctrine']['integration_enabled']) {
            return;
        }
        // We only tag the doctrine event subscriber if there are domains listed in the config...
        if (!(isset($config['domains']) && !empty($config['domains']))) {
            return;
        }

        $connections = array_filter($config['doctrine']['connections']);
        if (empty($connections)) {
            $container->getDefinition('ldap_tools.doctrine.event_listener.ldap_object')->addTag(
                'doctrine.event_subscriber'
            );
        } else {
            foreach ($connections as $connection) {
                $container->getDefinition('ldap_tools.doctrine.event_listener.ldap_object')->addTag(
                    'doctrine.event_subscriber',
                    ['connection' => $connection]
                );
            }
        }
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

        // Only tag the cache warmer if there are domains listed in the config...
        if (isset($config['domains']) && !empty($config['domains'])) {
            $ldapCfg['domains'] = $config['domains'];
            $container->getDefinition('ldap_tools.cache_warmer.ldap_tools_cache_warmer')->addTag('kernel.cache_warmer');
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

        $container->setParameter('ldap_tools.security.role_mapper.options', [
            'check_groups_recursively' => $config['check_groups_recursively'],
            'roles' => $roles,
            'role_attributes' => $config['role_attributes'],
            'role_ldap_type' => $config['role_ldap_type'],
            'default_role' => $config['default_role'],
        ]);
        $container->setParameter('ldap_tools.security.additional_attributes', $additionalAttributes);
        $container->setParameter('ldap_tools.security.user', $config['user']);

        $container->getDefinition('ldap_tools.security.user.ldap_user_provider')->addMethodCall(
            'setLdapObjectType',
            [$config['ldap_object_type']]
        );

        $userProviderDef = $container->getDefinition('ldap_tools.security.user.ldap_user_provider');
        if (isset($config['search_base'])) {
            $userProviderDef->addMethodCall(
                'setSearchBase',
                [$config['search_base']]
            );
        }
        $userProviderDef->addMethodCall(
            'setRefreshAttributes',
            [$config['refresh_user_attributes']]
        );
        $userProviderDef->addMethodCall(
            'setRefreshRoles',
            [$config['refresh_user_roles']]
        );
    }

    protected function setGuardConfiguration(ContainerBuilder $container, array $config)
    {
        $container->setParameter('ldap_tools.security.guard.auth_success',  [
            'default_target_path' => $config['default_target_path'],
            'always_use_target_path' => $config['always_use_target_path'],
            'target_path_parameter' => $config['target_path_parameter'],
            'use_referrer' => $config['use_referrer'],
            'login_path' => $config['login_path'],
        ]);
        $container->setParameter('ldap_tools.security.guard.auth_failure', [
            'failure_path' => $config['failure_path'],
            'failure_forward' => $config['failure_forward'],
            'failure_path_parameter' => $config['failure_path_parameter'],
            'login_path' => $config['login_path'],
        ]);
        $container->setParameter('ldap_tools.security.guard.options',  [
            'username_parameter' => $config['username_parameter'],
            'password_parameter' => $config['password_parameter'],
            'domain_parameter' => $config['domain_parameter'],
            'post_only' => $config['post_only'],
            'remember_me' => $config['remember_me']
        ]);
        $container->getDefinition('ldap_tools.security.authentication.form_entry_point')
            ->addArgument(new Reference('security.http_utils'))
            ->addArgument($config['login_path'])
            ->addArgument($config['use_forward']);
    }
}
