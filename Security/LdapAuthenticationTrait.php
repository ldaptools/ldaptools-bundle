<?php
/**
 * This file is part of the LdapToolsBundle package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace LdapTools\Bundle\LdapToolsBundle\Security;

use LdapTools\Bundle\LdapToolsBundle\Security\User\LdapUserProvider;
use LdapTools\Exception\Exception;
use LdapTools\LdapManager;
use LdapTools\Object\LdapObject;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;
use Symfony\Component\Security\Core\Exception\CustomUserMessageAuthenticationException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;

/**
 * Common methods between the Guard and Authentication Provider.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
trait LdapAuthenticationTrait
{
    /**
     * @var LdapManager
     */
    protected $ldap;

    /**
     * @var LdapUserProvider
     */
    protected $ldapUserProvider;

    /**
     * The logic for determining the username/DN to bind with is as follows:
     *
     * 1. Always prefer a DN from a default user from the LDAP user provider, or LdapObject instance from LdapTools
     * 2. If it wasn't a LdapObject and no attribute was explicitly set to query LDAP for, use the UserInterface username
     * 3. Query LDAP using a specific attribute for a user with the specified username, return the DN.
     *
     * @param UserInterface $user
     * @param string|null $queryAttribute
     * @return string
     */
    protected function getBindUsername(UserInterface $user, $queryAttribute)
    {
        if ($user instanceof LdapObject && $user->has('dn')) {
            return $user->get('dn');
        }
        if ($queryAttribute === null) {
            return $user->getUsername();
        }

        return $this->ldapUserProvider
            ->getLdapUser($queryAttribute, $user->getUsername())
            ->get('dn');
    }

    /**
     * If no LDAP credentials are in the config then attempt to use the user supplied credentials from the login. But
     * only if we are using the LdapUserProvider.
     *
     * @param string $username
     * @param string $password
     * @param UserProviderInterface $userProvider
     */
    protected function setLdapCredentialsIfNeeded($username, $password, UserProviderInterface $userProvider)
    {
        // Only care about this in the context of the LDAP user provider...
        if (!$userProvider instanceof LdapUserProvider) {
            return;
        }

        // Only if the username/password are not defined in the config....
        $config = $this->ldap->getConnection()->getConfig();
        if (!(empty($config->getUsername()) && (empty($config->getPassword() && $config->getPassword() !== '0')))) {
            return;
        }

        $config->setUsername($username);
        $config->setPassword($password);
    }

    /**
     * If the domain needs to a different context for the request, then switch it.
     *
     * @param string|null $domain
     */
    protected function switchDomainIfNeeded($domain)
    {
        if (!empty($domain) && $this->ldap->getDomainContext() !== $domain) {
            $this->ldap->switchDomain($domain);
        }
    }

    /**
     * If the passed domain is not the current context, then switch back to it.
     *
     * @param string $domain
     */
    protected function switchDomainBackIfNeeded($domain)
    {
        if ($domain !== $this->ldap->getDomainContext()) {
            $this->ldap->switchDomain($domain);
        }
    }

    /**
     * Determine whether or not the exception should be masked with a BadCredentials or not.
     *
     * @param \Exception $e
     * @param bool $hideUserNotFoundExceptions
     * @throws \Exception
     */
    protected function hideOrThrow(\Exception $e, $hideUserNotFoundExceptions)
    {
        if ($hideUserNotFoundExceptions) {
            throw new BadCredentialsException('Bad credentials.', 0, $e);
        }

        // Specifically show LdapTools related exceptions, ignore others.
        // Custom auth exception messages don't exist until Symfony 2.8, 2.7 is still under support...
        if (!$hideUserNotFoundExceptions && $e instanceof Exception && class_exists('Symfony\Component\Security\Core\Exception\CustomUserMessageAuthenticationException')) {
            throw new CustomUserMessageAuthenticationException($e->getMessage(), [], $e->getCode());
        }

        throw $e;
    }
}
