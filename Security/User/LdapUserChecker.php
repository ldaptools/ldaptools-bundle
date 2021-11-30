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

use LdapTools\Enums\AD\ResponseCode;
use LdapTools\Connection\LdapConnection;
use Symfony\Component\Security\Core\Exception\CredentialsExpiredException;
use Symfony\Component\Security\Core\Exception\DisabledException;
use Symfony\Component\Security\Core\Exception\LockedException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserCheckerInterface;

/**
 * Interpret extended LDAP codes from authentication to determine the state of the LDAP account.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class LdapUserChecker implements UserCheckerInterface
{
    /**
     * {@inheritdoc}
     */
    public function checkPreAuth(UserInterface $user)
    {
        if (!$user instanceof LdapUser) {
            return;
        }

        if (!$user->isAccountNonLocked()) {
            $ex = new LockedException('User account is locked.');
            $ex->setUser($user);
            throw $ex;
        }

        if (!$user->isEnabled()) {
            $ex = new DisabledException('User account is disabled.');
            $ex->setUser($user);
            throw $ex;
        }

        if (!$user->isAccountNonExpired()) {
            $ex = new AccountExpiredException('User account has expired.');
            $ex->setUser($user);
            throw $ex;
        }
    }

    /**
     * {@inheritdoc}
     */
    public function checkPostAuth(UserInterface $user)
    {
        if (!$user instanceof LdapUser) {
            return;
        }

        if (!$user->isCredentialsNonExpired()) {
            $ex = new CredentialsExpiredException('User credentials have expired.');
            $ex->setUser($user);
            throw $ex;
        }
    }

    /**
     * Based on the LDAP error code and the LDAP type, throw any specific exceptions detected.
     *
     * @param UserInterface $user The user object.
     * @param int $code The extended LDAP error code.
     * @param string $ldapType The LDAP type used for authentication.
     */
    public function checkLdapErrorCode(UserInterface $user, $code, $ldapType)
    {
        if ($ldapType == LdapConnection::TYPE_AD && $code == ResponseCode::AccountLocked) {
            $ex = new LockedException('User account is locked.');
            $ex->setUser($user);
            throw $ex;
        }

        if ($ldapType == LdapConnection::TYPE_AD && $code == ResponseCode::AccountPasswordMustChange) {
            $ex = new CredentialsExpiredException('User credentials have expired.');
            $ex->setUser($user);
            throw $ex;
        }

        if ($ldapType == LdapConnection::TYPE_AD && $code == ResponseCode::AccountDisabled) {
            $ex = new DisabledException('User account is disabled.');
            $ex->setUser($user);
            throw $ex;
        }
    }
}
