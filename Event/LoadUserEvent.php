<?php
/**
 * This file is part of the LdapToolsBundle package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace LdapTools\Bundle\LdapToolsBundle\Event;

use LdapTools\Bundle\LdapToolsBundle\Security\User\LdapUser;
use LdapTools\Object\LdapObject;
use Symfony\Component\EventDispatcher\EventDispatcher;
use Symfony\Component\Security\Core\User\UserInterface;

/**
 * Represents a User load event.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class LoadUserEvent extends EventDispatcher
{
    /**
     * The event name that happens before a user is loaded from the user provider.
     */
    const BEFORE = 'ldap_tools_bundle.load_user.before';

    /**
     * The event name that happens after a user is loaded from the user provider.
     */
    const AFTER = 'ldap_tools_bundle.load_user.after';

    /**
     * @var string
     */
    protected $username;

    /**
     * @var string
     */
    protected $domain;

    /**
     * @var UserInterface|LdapUser|null
     */
    protected $user;

    /**
     * @var LdapObject|null
     */
    protected $ldapObject;

    /**
     * @param $username
     * @param $domain
     * @param UserInterface|null $user
     * @param LdapObject|null $ldapObject
     */
    public function __construct($username, $domain, UserInterface $user = null, LdapObject $ldapObject = null)
    {
        $this->username = $username;
        $this->domain = $domain;
        $this->user = $user;
        $this->ldapObject = $ldapObject;
    }

    /**
     * @return string
     */
    public function getUsername()
    {
        return $this->username;
    }

    /**
     * @return string
     */
    public function getDomain()
    {
        return $this->domain;
    }

    /**
     * This is only available on an AFTER load event. Otherwise it will be null.
     *
     * @return LdapUser|null|UserInterface
     */
    public function getUser()
    {
        return $this->user;
    }

    /**
     * Get the LDAP object the user was created from. This is only available on an AFTER load event.
     *
     * @return LdapObject|null
     */
    public function getLdapObject()
    {
        return $this->ldapObject;
    }
}
