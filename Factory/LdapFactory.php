<?php
/**
 * This file is part of the LdapToolsBundle package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace LdapTools\Bundle\LdapToolsBundle\Factory;

use LdapTools\Connection\LdapConnection;
use LdapTools\DomainConfiguration;

/**
 * Used to assist in making components needing active connections more spec/test'able.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class LdapFactory
{
    /**
     * @param string $domain
     * @return DomainConfiguration
     */
    public function getConfig($domain)
    {
        return new DomainConfiguration($domain);
    }

    /**
     * @param DomainConfiguration $config
     * @return LdapConnection
     */
    public function getConnection(DomainConfiguration $config)
    {
        return new LdapConnection($config);
    }
}
