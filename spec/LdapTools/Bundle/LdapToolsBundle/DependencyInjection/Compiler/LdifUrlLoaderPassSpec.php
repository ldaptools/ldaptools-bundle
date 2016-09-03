<?php
/**
 * This file is part of the LdapToolsBundle package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace spec\LdapTools\Bundle\LdapToolsBundle\DependencyInjection\Compiler;

use LdapTools\Bundle\LdapToolsBundle\DependencyInjection\Compiler\LdifUrlLoaderPass;
use PhpSpec\ObjectBehavior;
use Prophecy\Argument;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;
use Symfony\Component\DependencyInjection\Reference;

class LdifUrlLoaderPassSpec extends ObjectBehavior
{
    function it_is_initializable()
    {
        $this->shouldHaveType('LdapTools\Bundle\LdapToolsBundle\DependencyInjection\Compiler\LdifUrlLoaderPass');
    }

    function it_should_process_tagged_services_when_there_are_none_found(ContainerBuilder $container)
    {
        $container->findTaggedServiceIds(LdifUrlLoaderPass::LDIF_URL_LOADER_TAG)->willReturn([]);
        $container->findDefinition(Argument::any())->shouldNotBeCalled();

        $this->process($container);
    }

    function it_should_process_tagged_services_when_they_exist(ContainerBuilder $container, Definition $definition)
    {
        $id = 'foo.ldif_url_loader';
        $container->findTaggedServiceIds(LdifUrlLoaderPass::LDIF_URL_LOADER_TAG)->willReturn(
            [$id => [['type' => 'foo']]]
        );
        $container->findDefinition(LdifUrlLoaderPass::LDIF_PARSER)->shouldBeCalled()->willReturn($definition);
        $definition->addMethodCall('setUrlLoader', ['foo', new Reference($id)])->shouldBeCalled();

        $this->process($container);
    }

    function it_should_require_the_type_property_for_the_tag(ContainerBuilder $container, Definition $definition)
    {
        $id = 'foo.ldif_url_loader';
        $container->findTaggedServiceIds(LdifUrlLoaderPass::LDIF_URL_LOADER_TAG)->willReturn([$id => [[]]]);
        $container->findDefinition(LdifUrlLoaderPass::LDIF_PARSER)->shouldBeCalled()->willReturn($definition);

        $this->shouldThrow(new \InvalidArgumentException('Service "foo.ldif_url_loader" must define the "type" attribute on "ldap_tools.ldif_url_loader" tags.'))->duringProcess($container);
    }
}
