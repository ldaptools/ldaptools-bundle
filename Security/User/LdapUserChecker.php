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

use LdapTools\Connection\ADResponseCodes;
use LdapTools\Connection\LdapConnection;
use Symfony\Component\Security\Core\Exception\CredentialsExpiredException;
use Symfony\Component\Security\Core\Exception\DisabledException;
use Symfony\Component\Security\Core\Exception\LockedException;
use Symfony\Component\Security\Core\User\UserChecker;
use Symfony\Component\Security\Core\User\UserInterface;

/**
 * Interpret extended LDAP codes from authentication to determine the state of the LDAP account.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class LdapUserChecker extends UserChecker
{
    /**
     * Based on the LDAP error code and the LDAP type, throw any specific exceptions detected.
     *
     * @param UserInterface $user The user object.
     * @param int $code The extended LDAP error code.
     * @param string $ldapType The LDAP type used for authentication.
     */
    public function checkLdapErrorCode(UserInterface $user, $code, $ldapType)
    {
        if ($ldapType == LdapConnection::TYPE_AD && $code == ADResponseCodes::ACCOUNT_LOCKED) {
            $ex = new LockedException('User account is locked.');
            $ex->setUser($user);
            throw $ex;
        }

        if ($ldapType == LdapConnection::TYPE_AD && $code == ADResponseCodes::ACCOUNT_PASSWORD_MUST_CHANGE) {
            $ex = new CredentialsExpiredException('User credentials have expired.');
            $ex->setUser($user);
            throw $ex;
        }

        if ($ldapType == LdapConnection::TYPE_AD && $code == ADResponseCodes::ACCOUNT_DISABLED) {
            $ex = new DisabledException('User account is disabled.');
            $ex->setUser($user);
            throw $ex;
        }
    }
}
