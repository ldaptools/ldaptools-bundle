<?php
/**
 * This file is part of the LdapToolsBundle package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace LdapTools\Bundle\LdapToolsBundle\DependencyInjection\Compiler;

use Symfony\Component\DependencyInjection\Compiler\CompilerPassInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Reference;

/**
 * Add any services tagged as a LDIF URL loader to the LDIF parser service.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class LdifUrlLoaderPass implements CompilerPassInterface
{
    /**
     * The LDIF URL loader tag name.
     */
    const LDIF_URL_LOADER_TAG = 'ldap_tools.ldif_url_loader';

    /**
     * The LDIF parser service name.
     */
    const LDIF_PARSER = 'ldap_tools.ldif_parser';

    /**
     * {@inheritdoc}
     */
    public function process(ContainerBuilder $container)
    {
        $urlLoaders = $container->findTaggedServiceIds(self::LDIF_URL_LOADER_TAG);
        if (empty($urlLoaders)) {
            return;
        }
        $parser = $container->findDefinition(self::LDIF_PARSER);

        foreach ($urlLoaders as $id => $loader) {
            if (!isset($loader[0]['type'])) {
                throw new \InvalidArgumentException(sprintf('Service "%s" must define the "type" attribute on "%s" tags.', $id, self::LDIF_URL_LOADER_TAG));
            }
            $parser->addMethodCall('setUrlLoader', [$loader[0]['type'], new Reference($id)]);
        }
    }
}
