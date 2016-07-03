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
use Symfony\Component\EventDispatcher\Event;
use Symfony\Component\Security\Core\User\UserInterface;

/**
 * Represents a LDAP login event.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class LdapLoginEvent extends Event
{
    /**
     * The event name when the login was successful
     */
    const SUCCESS = 'ldap_tools_bundle.login.success';

    /**
     * @var UserInterface|LdapUser
     */
    protected $user;

    /**
     * @param UserInterface|LdapUser $user
     */
    public function __construct(UserInterface $user)
    {
        $this->user = $user;
    }

    /**
     * @return UserInterface|LdapUser
     */
    public function getUser()
    {
        return $this->user;
    }
}
