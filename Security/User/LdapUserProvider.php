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

use LdapTools\Connection\LdapConnection;
use LdapTools\Exception\EmptyResultException;
use LdapTools\Exception\MultiResultException;
use LdapTools\Object\LdapObject;
use LdapTools\Object\LdapObjectType;
use Symfony\Component\Security\Core\Exception\UnsupportedUserException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Core\Exception\UsernameNotFoundException;
use LdapTools\LdapManager;

/**
 * Loads a user from LDAP.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class LdapUserProvider implements UserProviderInterface
{
    /**
     * The base LdapUser class instantiated by this user provider.
     */
    const BASE_USER_CLASS = '\LdapTools\Bundle\LdapToolsBundle\Security\User\LdapUser';

    /**
     * @var LdapManager
     */
    protected $ldap;

    /**
     * @var array The map for the LDAP attribute names.
     */
    protected $attrMap = [];

    /**
     * @var array The role to LDAP group name map.
     */
    protected $roleMap = [];

    /**
     * @var array Any additional LDAP attributes to select.
     */
    protected $attributes = [];

    /**
     * @var string
     */
    protected $userClass = self::BASE_USER_CLASS;

    /**
     * @var bool Whether or not to check group membership recursively when checking role membership.
     */
    protected $checkGroupsRecursively;

    /**
     * @var string|null The default role to be assigned to a user.
     */
    protected $defaultRole;

    /**
     * @var string The object type to search LDAP for.
     */
    protected $ldapObjectType = LdapObjectType::USER;

    /**
     * @var string The container/OU to search for the user under.
     */
    protected $searchBase;

    /**
     * @param LdapManager $ldap
     * @param array $attrMap
     * @param array $roleMap
     * @param bool $checkGroupsRecursively
     */
    public function __construct(LdapManager $ldap, array $attrMap, array $roleMap, $checkGroupsRecursively = true)
    {
        $this->ldap = $ldap;
        $this->attrMap = $attrMap;
        $this->roleMap = $roleMap;
        $this->checkGroupsRecursively = $checkGroupsRecursively;
    }

    /**
     * Set the default role to add to a LDAP user.
     *
     * @param string|null $role
     */
    public function setDefaultRole($role)
    {
        if (is_string($role)) {
            $role = strtoupper($role);
        }
        $this->defaultRole = $role;
    }

    /**
     * Set the user class to be instantiated and returned from the LDAP provider.
     *
     * @param string $class
     */
    public function setUserClass($class)
    {
        if (!($class === self::BASE_USER_CLASS || is_subclass_of($class, self::BASE_USER_CLASS))) {
            throw new UnsupportedUserException(sprintf(
                'The LDAP user provider class "%s" must be an instance of "%s".',
                $class,
                self::BASE_USER_CLASS
            ));
        }

        $this->userClass = $class;
    }

    /**
     * Set any additional attributes to be selected for the LDAP user.
     *
     * @param array $attributes
     */
    public function setAttributes(array $attributes)
    {
        $this->attributes = $attributes;
    }

    /**
     * Set the LDAP object type that will be searched for.
     *
     * @param $type
     */
    public function setLdapObjectType($type)
    {
        $this->ldapObjectType = $type;
    }

    /**
     * @param string $searchBase
     */
    public function setSearchBase($searchBase)
    {
        $this->searchBase = $searchBase;
    }

    /**
     * {@inheritdoc}
     */
    public function loadUserByUsername($username)
    {
        return $this->searchForUser($this->attrMap['username'], $username);
    }

    /**
     * {@inheritdoc}
     */
    public function refreshUser(UserInterface $user)
    {
        if (!$user instanceof LdapUser) {
            throw new UnsupportedUserException(sprintf('Instances of "%s" are not supported.', get_class($user)));
        }

        return $this->searchForUser($this->attrMap['guid'], $user->getLdapGuid());
    }

    /**
     * {@inheritdoc}
     */
    public function supportsClass($class)
    {
        return ($class === self::BASE_USER_CLASS || is_subclass_of($class, self::BASE_USER_CLASS));
    }

    /**
     * Search for, and return, the LDAP user by a specific attribute.
     *
     * @param string $attribute
     * @param string $value
     * @return LdapUser
     */
    protected function searchForUser($attribute, $value)
    {
        try {
            $query = $this->ldap->buildLdapQuery()
                ->select($this->getAttributesToSelect())
                ->from($this->ldapObjectType)
                ->where([$attribute => $value]);
            if (!is_null($this->searchBase)) {
                $query->setBaseDn($this->searchBase);
            }
            $ldapUser = $query->getLdapQuery()->getSingleResult();
        } catch (EmptyResultException $e) {
            throw new UsernameNotFoundException(sprintf('Username "%s" was not found.', $value));
        } catch (MultiResultException $e) {
            throw new UsernameNotFoundException(sprintf('Multiple results for "%s" were found.', $value));
        }
        $user = $this->constructUserClass($ldapUser);
        $this->setRolesForUser($user, $ldapUser);

        return $user;
    }

    /**
     * Get all the attributes that should be selected for when querying LDAP.
     *
     * @return array
     */
    protected function getAttributesToSelect()
    {
        $attributes = array_values($this->attrMap);
        if (!empty($this->attributes)) {
            $attributes = array_merge($attributes, $this->attributes);
        }

        return $attributes;
    }

    /**
     * Set the roles for the user based on group membership.
     *
     * @param LdapUser $user
     * @param LdapObject $ldapUser
     */
    protected function setRolesForUser(LdapUser $user, LdapObject $ldapUser)
    {
        if ($this->defaultRole) {
            $user->addRole($this->defaultRole);
        }

        $groups = $ldapUser->get($this->attrMap['groups']);
        if ($this->checkGroupsRecursively && $this->ldap->getConnection()->getConfig()->getLdapType() == LdapConnection::TYPE_AD) {
            $query = $this->ldap->buildLdapQuery();
            $groups = $query->select('name')
                ->fromGroups()
                ->where($query->filter()->hasMemberRecursively($user->getLdapGuid()))
                ->getLdapQuery()
                ->getArrayResult();
            $groups = array_column($groups, 'name');
        }
        $groups = array_map('strtolower', $groups);

        foreach ($this->roleMap as $role => $roleGroups) {
            if (!empty(array_intersect($groups, array_map('strtolower', $roleGroups)))) {
                $user->addRole($role);
            }
        }
    }

    /**
     * @param LdapObject $ldapObject
     * @return LdapUser
     */
    protected function constructUserClass(LdapObject $ldapObject)
    {
        $errorMessage = 'Unable to instantiate user class "%s". Error was: %s';

        try {
            $user = new $this->userClass($ldapObject, $this->attrMap);
        } catch (\Throwable $e) {
            throw new UnsupportedUserException(sprintf($errorMessage, $this->userClass, $e->getMessage()));
        // Unlikely to help much in PHP 5.6, but oh well...
        } catch (\Exception $e) {
            throw new UnsupportedUserException(sprintf($errorMessage, $this->userClass, $e->getMessage()));
        }

        return $user;
    }
}
