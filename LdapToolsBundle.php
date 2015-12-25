<?php
/**
 * This file is part of the LdapToolsBundle package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace LdapTools\Bundle\LdapToolsBundle;

use LdapTools\Bundle\LdapToolsBundle\DependencyInjection\Compiler\EventRegisterPass;
use LdapTools\Bundle\LdapToolsBundle\DependencyInjection\Security\Factory\LdapFormLoginFactory;
use LdapTools\Bundle\LdapToolsBundle\Doctrine\Type\LdapObjectCollectionType;
use LdapTools\Bundle\LdapToolsBundle\Doctrine\Type\LdapObjectType;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\HttpKernel\Bundle\Bundle;
use Doctrine\DBAL\Types\Type;

/**
 * The Bundle class.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class LdapToolsBundle extends Bundle
{
    public function __construct()
    {
        // It's useful to auto-register the types, but we should not assume they are using doctrine...
        if (!class_exists('\Doctrine\DBAL\Types\Type')) {
            return;
        }

        if (!Type::hasType(LdapObjectType::TYPE)) {
            Type::addType(
                LdapObjectType::TYPE,
                '\LdapTools\Bundle\LdapToolsBundle\Doctrine\Type\LdapObjectType'
            );
        }
        if (!Type::hasType(LdapObjectCollectionType::TYPE)) {
            Type::addType(
                LdapObjectCollectionType::TYPE,
                '\LdapTools\Bundle\LdapToolsBundle\Doctrine\Type\LdapObjectCollectionType'
            );
        }
    }

    /**
     * Make Symfony aware of the LDAP listener factory and add the compiler pass.
     *
     * @param ContainerBuilder $container
     */
    public function build(ContainerBuilder $container)
    {
        parent::build($container);
        $extension = $container->getExtension('security');
        $extension->addSecurityListenerFactory(new LdapFormLoginFactory());
        $container->addCompilerPass(new EventRegisterPass());
    }
}
