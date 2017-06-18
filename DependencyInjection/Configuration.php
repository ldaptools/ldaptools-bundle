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

use Symfony\Component\Config\Definition\Builder\ArrayNodeDefinition;
use Symfony\Component\Config\Definition\Builder\TreeBuilder;
use Symfony\Component\Config\Definition\ConfigurationInterface;

/**
 * LdapToolsBundle configuration options.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class Configuration implements ConfigurationInterface
{
    /**
     * @var bool Whether or not debug mode is in use.
     */
    protected $debug;

    /**
     * @param bool $debug
     */
    public function __construct($debug)
    {
        $this->debug = (bool) $debug;
    }

    /**
     * {@inheritDoc}
     */
    public function getConfigTreeBuilder()
    {
        $treeBuilder = new TreeBuilder();
        $rootNode = $treeBuilder->root('ldap_tools');
        $this->addMainSection($rootNode);
        $this->addDoctrineSection($rootNode);
        $this->addGeneralSection($rootNode);
        $this->addLdapDomainsSection($rootNode);
        $this->addSecuritySection($rootNode);

        return $treeBuilder;
    }

    /**
     * @param ArrayNodeDefinition $node
     */
    protected function addMainSection(ArrayNodeDefinition $node)
    {
        $node->children()
            ->booleanNode('logging')->defaultValue($this->debug)->end()
            ->booleanNode('profiling')->defaultValue($this->debug)->end()
            ->end();
    }

    /**
     * @param ArrayNodeDefinition $node
     */
    protected function addDoctrineSection(ArrayNodeDefinition $node)
    {
        $node
            ->children()
            ->arrayNode('doctrine')
                ->addDefaultsIfNotSet()
                ->children()
                    ->booleanNode('integration_enabled')->defaultTrue()
                        ->info('Whether or not Doctrine integration should be used (adds a subscriber for lifecycle events)')->end()
                    ->arrayNode('connections')
                        ->info('Only use doctrine integration on a specific connection name(s)')
                        ->beforeNormalization()
                            ->ifTrue(function ($v) {
                                return !is_array($v);
                            })
                            ->then(function ($v) {
                                return [$v];
                            })
                            ->end()
                        ->prototype('scalar')->end()
                        ->end()
                    ->end()
                ->end()
            ->end();
    }

    /**
     * @param ArrayNodeDefinition $node
     */
    private function addGeneralSection(ArrayNodeDefinition $node)
    {
        $node
            ->children()
            ->arrayNode('general')
                ->addDefaultsIfNotSet()
                ->children()
                    ->scalarNode('default_domain')
                        ->info('If more than one domain is defined, explicitly set which is the default context for the LdapManager (by domain_name)')->end()
                    ->scalarNode('schema_format')->end()
                    ->scalarNode('schema_folder')->end()
                    ->scalarNode('cache_type')->defaultValue($this->debug ? 'none' : 'doctrine')->end()
                    ->arrayNode('cache_options')
                        ->addDefaultsIfNotSet()
                        ->children()
                            ->scalarNode('cache_folder')->defaultValue('%kernel.cache_dir%/ldaptools')->end()
                            ->booleanNode('cache_auto_refresh')->defaultFalse()->end()
                            ->end()
                        ->end()
                    ->arrayNode('attribute_converters')->end()
                    ->end()
                ->end()
            ->end();
    }

    /**
     * @param ArrayNodeDefinition $node
     */
    private function addLdapDomainsSection(ArrayNodeDefinition $node)
    {
        $node
            ->children()
                ->arrayNode('domains')
                ->prototype('array')
                ->children()
                    ->scalarNode('domain_name')->isRequired()
                        ->info('The FQDN (ie. example.com)')->end()
                    ->scalarNode('username')
                        ->info('The username/DN/SID/GUID used to connect to LDAP.')->end()
                    ->scalarNode('password')
                        ->info('The password for the username used to connect to LDAP.')->end()
                    ->scalarNode('base_dn')
                        ->info('The base DN used for searches (ie. dc=example,dc=com). This is queried from the RootDSE if not provided.')->end()
                    ->integerNode('port')
                        ->info('The default port number to connect to LDAP on.')->end()
                    ->booleanNode('use_paging')
                        ->info('Whether or not search results should be paged')->end()
                    ->integerNode('page_size')
                        ->info('The size for paged result searches.')->end()
                    ->booleanNode('use_tls')
                        ->info('Encrypt the connection with TLS. This is required when modifying LDAP passwords.')->end()
                    ->booleanNode('use_ssl')
                        ->info('Encrypt the connection with SSL. Typically you want to use "use_tls" and not this option.')->end()
                    ->scalarNode('ldap_type')
                        ->info('The LDAP type for this domain. Choices are ad or openldap.')->end()
                    ->arrayNode('servers')
                        ->info('The LDAP servers to connect to. This is queried from DNS if not provided.')
                        ->beforeNormalization()
                            ->ifTrue(function ($v) {
                                return !is_array($v);
                            })
                            ->then(function ($v) {
                                return [$v];
                            })
                            ->end()
                        ->prototype('scalar')->end()
                        ->end()
                    ->booleanNode('lazy_bind')
                        ->info('When set to true, then the connection will not automatically connect and bind when first created.')->defaultTrue()->end()
                    ->integerNode('idle_reconnect')
                        ->info('The elapsed time (in seconds) when an idle connection will attempt to reconnect to LDAP.')->end()
                    ->integerNode('connect_timeout')
                        ->info('The elapsed time (in seconds) to wait while attempting the initial connection to LDAP.')->end()
                    ->scalarNode('server_selection')
                        ->info('Determines how the LDAP server is selected. Can be "order" or "random".')->end()
                    ->scalarNode('encoding')->end()
                    ->scalarNode('schema_name')
                        ->info('The schema name to use for this domain')->end()
                    ->scalarNode('bind_format')
                        ->info('Set to a string that determines where the username is placed in a bind attempt: %%username%%,ou=users,dc=foo,dc=bar')->end()
                    ->arrayNode('ldap_options')
                        ->info('Set specific LDAP_OPT_* constants to use. Specify them using their string name as keys along with their values.')
                        ->useAttributeAsKey('name')
                        ->prototype('variable')
                        ->end()
                ->end()
        ->end();
    }

    /**
     * @param ArrayNodeDefinition $node
     */
    protected function addSecuritySection(ArrayNodeDefinition $node)
    {
        $node
            ->children()
                ->arrayNode('security')
                    ->addDefaultsIfNotSet()
                    ->children()
                    ->scalarNode('search_base')->defaultNull()
                        ->info('The default DN to start the user search from.')->end()
                    ->scalarNode('ldap_object_type')->defaultValue('user')
                        ->info('The LdapTools object type for the user provider to search for.')->end()
                    ->scalarNode('default_role')->defaultValue('ROLE_USER')
                        ->info('Regardless of group membership this role will be assigned to the loaded user. Set it to null for no roles to be assigned by default.')->end()
                    ->booleanNode('check_groups_recursively')
                        ->info('If set to true then group membership will contain all groups, and nested groups, the user belongs to.')->defaultTrue()->end()
                    ->scalarNode('user')->defaultValue('\LdapTools\Bundle\LdapToolsBundle\Security\User\LdapUser')
                        ->info('The user class that the LDAP user provider will instantiate. It must implement the LdapUserInterface.')->end()
                    ->arrayNode('guard')
                        ->info('Guard specific configuration options.')
                        ->addDefaultsIfNotSet()
                        ->children()
                            ->scalarNode('login_path')->defaultValue('/login')->end()
                            ->scalarNode('default_target_path')->defaultValue('/')->end()
                            ->booleanNode('always_use_target_path')->defaultFalse()->end()
                            ->scalarNode('target_path_parameter')->defaultValue('_target_path')->end()
                            ->booleanNode('use_referrer')->defaultFalse()->end()
                            ->scalarNode('failure_path')->defaultNull()->end()
                            ->booleanNode('failure_forward')->defaultFalse()->end()
                            ->scalarNode('failure_path_parameter')->defaultValue('_failure_path')->end()
                            ->scalarNode('username_parameter')->defaultValue('_username')->end()
                            ->scalarNode('password_parameter')->defaultValue('_password')->end()
                            ->scalarNode('domain_parameter')->defaultValue('_ldap_domain')->end()
                            ->booleanNode('use_forward')->defaultFalse()->end()
                            ->booleanNode('post_only')->defaultFalse()->end()
                            ->booleanNode('remember_me')->defaultFalse()->end()
                        ->end()
                    ->end()
                    ->arrayNode('additional_attributes')
                        ->info('Any additional attribute values that should be available when the user is loaded.')
                        ->prototype('scalar')->end()
                        ->end()
                    ->arrayNode('roles')
                        ->info('Map LDAP group names to specific roles. If a user is a member of the group they will get the role mapped to it.')
                        ->useAttributeAsKey('name')
                        ->prototype('array')
                        ->beforeNormalization()
                            ->ifTrue(function ($v) {
                                return !is_array($v);
                            })
                            ->then(function ($v) {
                                return [$v];
                            })
                            ->end()
                        ->prototype('scalar')->end()
                        ->end()
                        ->end()
                    ->scalarNode('role_ldap_type')->defaultValue('group')
                        ->info('The LdapTools object type for the groups used to check for roles.')->end()
                    ->arrayNode('role_attributes')
                        ->info('When searching for groups/roles for a user, map to these attributes for GUID, SID, members, or name.')
                        ->addDefaultsIfNotSet()
                        ->children()
                            ->scalarNode('name')->defaultValue('name')->end()
                            ->scalarNode('sid')->defaultValue('sid')->end()
                            ->scalarNode('guid')->defaultValue('guid')->end()
                            ->scalarNode('members')->defaultValue('members')->end()
                            ->end()
                        ->end()
                    ->booleanNode('refresh_user_attributes')
                        ->info('Set this to true if you want user attributes re-queried on a user refresh.')->defaultFalse()->end()
                    ->booleanNode('refresh_user_roles')
                        ->info('Set this to true if you want user roles re-queried on a user refresh.')->defaultFalse()->end()
                    ->end()
                ->end()
            ->end();
    }
}
