<?php
/**
 * This file is part of the LdapToolsBundle package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace LdapTools\Bundle\LdapToolsBundle\DependencyInjection\Security\Factory;

use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Reference;
use Symfony\Bundle\SecurityBundle\DependencyInjection\Security\Factory\FormLoginFactory;

/**
 * The LDAP form login factory.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class LdapFormLoginFactory extends FormLoginFactory
{
    public function __construct()
    {
        parent::__construct();
        $this->addOption('domain_parameter', '_ldap_domain');
    }

    /**
     * {@inheritdoc}
     */
    public function getKey(): string
    {
        return 'ldap-tools-form';
    }

    /**
     * {@inheritdoc}
     */
    protected function getListenerId(): string
    {
        return 'ldap_tools.security.firewall.ldap_form_login_listener';
    }

    /**
     * {@inheritdoc}
     */
    protected function createAuthProvider(ContainerBuilder $container, $id, $config, $userProviderId): string
    {
        $provider = 'ldap_tools.security.user.ldap_user_provider.'.$id;
        $decorator = class_exists('Symfony\Component\DependencyInjection\ChildDefinition') ?
            'Symfony\Component\DependencyInjection\ChildDefinition' :
            'Symfony\Component\DependencyInjection\DefinitionDecorator';

        $container->setDefinition($provider, new $decorator('ldap_tools.security.authentication.ldap_authentication_provider'))
            ->replaceArgument(0, $id)
            ->replaceArgument(2, new Reference($userProviderId));

        return $provider;
    }
}
