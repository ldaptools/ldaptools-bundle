<?php
/**
 * This file is part of the LdapToolsBundle package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace LdapTools\Bundle\LdapToolsBundle\Security\User;

/**
 * Any user loaded from the LdapUserProvider must implement this interface.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface LdapUserInterface
{
    /**
     * Sets the username for the user.
     *
     * @param string $username
     */
    public function setUsername($username);

    /**
     * Set the GUID used to uniquely identify the user in LDAP.
     *
     * @param string $guid
     */
    public function setLdapGuid($guid);

    /**
     * Get the GUID used to uniquely identify the user in LDAP.
     *
     * @return string
     */
    public function getLdapGuid();

    /**
     * Sets the roles for the user.
     *
     * @param array $roles
     */
    public function setRoles(array $roles);
}
