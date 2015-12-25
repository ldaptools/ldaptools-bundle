<?php
/**
 * This file is part of the LdapToolsBundle package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace spec\LdapTools\Bundle\LdapToolsBundle\DependencyInjection\Security\Factory;

use PhpSpec\ObjectBehavior;
use Prophecy\Argument;
use Symfony\Component\DependencyInjection\Reference;
use Symfony\Component\HttpKernel\Kernel;

class LdapFormLoginFactorySpec extends ObjectBehavior
{
    function it_is_initializable()
    {
        $this->shouldHaveType('LdapTools\Bundle\LdapToolsBundle\DependencyInjection\Security\Factory\LdapFormLoginFactory');
    }

    function it_should_get_the_key()
    {
        $this->getKey()->shouldBeEqualTo('ldap-tools-form');
    }

    /**
     * @param \Symfony\Component\DependencyInjection\ContainerBuilder $container
     * @param \Symfony\Component\DependencyInjection\Definition $upDefinition
     * @param \Symfony\Component\DependencyInjection\Definition $definition
     */
    function it_should_create_the_listener_and_provider_ids($container, $upDefinition, $definition)
    {
        $id = 'restricted';
        $entryPoint = 'foo';
        $userProviderId = 'ldap_tools.security.user.ldap_user_provider';
        $listenerId = 'ldap_tools.security.firewall.ldap_form_login_listener';
        $options = ['remember_me' => false, 'login_path' => '/login', 'use_forward' => false];

        $ignoredDefs = [
            "security.authentication.success_handler.restricted.ldap_tools_form",
            "security.authentication.failure_handler.restricted.ldap_tools_form",
            "security.authentication.form_entry_point.".$id,
        ];

        // Container expectations...
        $container->setDefinition("$userProviderId.".$id, Argument::any())->shouldBeCalled()->willReturn($upDefinition);
        $container->setDefinition("$listenerId.$id", Argument::any())->willReturn($definition);
        $container->getDefinition("$listenerId.".$id, Argument::any())->willReturn($definition);

        // Not concerned with these really, but need to add them...
        foreach ($ignoredDefs as $def) {
            $container->setDefinition($def, Argument::any())->willReturn($definition);
        }
        $definition->addMethodCall(Argument::any(), Argument::any())->willReturn($definition);
        $definition->replaceArgument(Argument::any(), Argument::any())->willReturn($definition);
        $definition->addArgument(Argument::any(), Argument::any())->willReturn($definition);

        // UserProvider expectations...
        $upDefinition->replaceArgument(0, $id)->shouldBeCalled()->willReturn($upDefinition);
        $upDefinition->replaceArgument(2, new Reference($userProviderId))->shouldBeCalled()->willReturn($upDefinition);

        $this->create($container, $id, $options, $userProviderId, $entryPoint)->shouldBeEqualTo([
            "$userProviderId.$id",
            "$listenerId.".$id,
            "security.authentication.form_entry_point.restricted",
        ]);
    }
}
