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

use LdapTools\BatchModify\BatchCollection;
use LdapTools\Bundle\LdapToolsBundle\Event\LoadUserEvent;
use LdapTools\Connection\LdapConnection;
use LdapTools\Exception\EmptyResultException;
use LdapTools\Exception\MultiResultException;
use LdapTools\Object\LdapObject;
use LdapTools\Object\LdapObjectCollection;
use LdapTools\Object\LdapObjectType;
use LdapTools\Utilities\LdapUtilities;
use Symfony\Component\EventDispatcher\EventDispatcherInterface;
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
     * @var LdapManager
     */
    protected $ldap;

    /**
     * @var EventDispatcherInterface
     */
    protected $dispatcher;

    /**
     * @var array The role to LDAP group name map.
     */
    protected $roleMap = [];

    /**
     * @var array Map names to their LDAP attribute names when querying for LDAP groups used for roles.
     */
    protected $roleAttrMap = [
        'name' => 'name',
        'sid' => 'sid',
        'guid' => 'guid',
        'members' => 'members',
    ];

    /**
     * @var array Default attributes selected for the Advanced User Interface.
     */
    protected $defaultAttributes = [
        'username',
        'guid',
        'accountExpirationDate',
        'enabled',
        'groups',
        'locked',
        'passwordMustChange',
    ];

    /**
     * @var array Any additional LDAP attributes to select.
     */
    protected $additionalAttributes = [];

    /**
     * @var string
     */
    protected $userClass = LdapUser::class;

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
     * @var string The group object type when searching group membership.
     */
    protected $groupObjectType = LdapObjectType::GROUP;
    
    /**
     * @var string The container/OU to search for the user under.
     */
    protected $searchBase;

    /**
     * @var bool Whether or not user attributes should be re-queried on a refresh.
     */
    protected $refreshAttributes = true;

    /**
     * @var bool Whether or not user roles should be re-queried on a refresh.
     */
    protected $refreshRoles = true;

    /**
     * @param LdapManager $ldap
     * @param EventDispatcherInterface $dispatcher
     * @param array $roleMap
     * @param bool $checkGroupsRecursively
     */
    public function __construct(LdapManager $ldap, EventDispatcherInterface $dispatcher, array $roleMap, $checkGroupsRecursively = true)
    {
        $this->ldap = $ldap;
        $this->dispatcher = $dispatcher;
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
        if (!$this->supportsClass($class)) {
            throw new UnsupportedUserException(sprintf(
                'The LDAP user provider class "%s" must implement "%s".',
                $class,
                LdapUserInterface::class
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
        $this->additionalAttributes = $attributes;
    }

    /**
     * Set the LDAP object type that will be searched for.
     *
     * @param string $type
     */
    public function setLdapObjectType($type)
    {
        $this->ldapObjectType = $type;
    }

    /**
     * Set the LdapTools object type to search for group membership.
     *
     * @param string $type
     */
    public function setRoleLdapType($type)
    {
        $this->groupObjectType = $type;
    }

    /**
     * Set the attribute name to LDAP name attributes used in querying LDAP groups for roles.
     *
     * @param array $map
     */
    public function setRoleAttributeMap(array $map)
    {
        $this->roleAttrMap = $map;
    }

    /**
     * @param string $searchBase
     */
    public function setSearchBase($searchBase)
    {
        $this->searchBase = $searchBase;
    }

    /**
     * @param bool $refreshRoles
     */
    public function setRefreshRoles($refreshRoles)
    {
        $this->refreshRoles = $refreshRoles;
    }

    /**
     * @param bool $refreshAttributes
     */
    public function setRefreshAttributes($refreshAttributes)
    {
        $this->refreshAttributes = $refreshAttributes;
    }

    /**
     * {@inheritdoc}
     */
    public function loadUserByUsername($username)
    {
        $this->dispatcher->dispatch(LoadUserEvent::BEFORE, new LoadUserEvent($username, $this->ldap->getDomainContext()));
        $ldapUser = $this->getLdapUser('username', $username);
        $user = $this->setRolesForUser($this->constructUserClass($ldapUser));
        $this->dispatcher->dispatch(LoadUserEvent::AFTER, new LoadUserEvent($username, $this->ldap->getDomainContext(), $user, $ldapUser));

        return $user;
    }

    /**
     * {@inheritdoc}
     */
    public function refreshUser(UserInterface $user)
    {
        if (!$user instanceof LdapUserInterface) {
            throw new UnsupportedUserException(sprintf('Instances of "%s" are not supported.', get_class($user)));
        }
        $roles = $user->getRoles();

        if ($this->refreshAttributes) {
            $user = $this->constructUserClass($this->getLdapUser('guid', $user->getLdapGuid()));
        }
        if ($this->refreshRoles) {
            $this->setRolesForUser($user);
        } else {
            $user->setRoles($roles);
        }

        return $user;
    }

    /**
     * {@inheritdoc}
     */
    public function supportsClass($class)
    {
        return is_subclass_of($class, LdapUserInterface::class);
    }

    /**
     * Search for, and return, the LDAP user by a specific attribute.
     *
     * @param string $attribute
     * @param string $value
     * @return LdapObject
     */
    protected function getLdapUser($attribute, $value)
    {
        try {
            $query = $this->ldap->buildLdapQuery()
                ->select($this->getAttributesToSelect())
                ->from($this->ldapObjectType)
                ->where([$attribute => $value]);
            if (!is_null($this->searchBase)) {
                $query->setBaseDn($this->searchBase);
            }
            return $query->getLdapQuery()->getSingleResult();
        } catch (EmptyResultException $e) {
            throw new UsernameNotFoundException(sprintf('Username "%s" was not found.', $value));
        } catch (MultiResultException $e) {
            throw new UsernameNotFoundException(sprintf('Multiple results for "%s" were found.', $value));
        }
    }

    /**
     * Get all the attributes that should be selected for when querying LDAP.
     *
     * @return array
     */
    protected function getAttributesToSelect()
    {
        return array_values(array_unique(array_filter(array_merge(
            $this->defaultAttributes,
            $this->additionalAttributes
        ))));
    }

    /**
     * Set the roles for the user based on group membership.
     *
     * @param LdapUserInterface $user
     * @return LdapUserInterface
     */
    protected function setRolesForUser(LdapUserInterface $user)
    {
        $roles = [];

        if ($this->defaultRole) {
            $roles[] = $this->defaultRole;
        }
        $groups = $this->getGroupsForUser($user);

        foreach ($this->roleMap as $role => $roleGroups) {
            if ($this->hasGroupForRoles($roleGroups, $groups)) {
                $roles[] = $role;
            }
        }
        $user->setRoles($roles);

        return $user;
    }

    /**
     * Check all of the groups that are valid for a specific role against all of the LDAP groups that the user belongs
     * to.
     *
     * @param array $roleGroups
     * @param LdapObjectCollection $ldapGroups
     * @return bool
     */
    protected function hasGroupForRoles(array $roleGroups, LdapObjectCollection $ldapGroups)
    {
        foreach ($roleGroups as $roleGroup) {
            if (LdapUtilities::isValidLdapObjectDn($roleGroup)) {
                $attribute = 'dn';
            } elseif (preg_match(LdapUtilities::MATCH_GUID, $roleGroup)) {
                $attribute = $this->roleAttrMap['guid'];
            } elseif (preg_match(LdapUtilities::MATCH_SID, $roleGroup)) {
                $attribute = $this->roleAttrMap['sid'];
            } else {
                $attribute = $this->roleAttrMap['name'];
            }

            if ($this->hasGroupWithAttributeValue($ldapGroups, $attribute, $roleGroup)) {
                return true;
            }
        }
        
        return false;
    }

    /**
     * Check each LDAP group to see if any of them have an attribute with a specific value.
     *
     * @param LdapObjectCollection $groups
     * @param string $attribute
     * @param string $value
     * @return bool
     */
    protected function hasGroupWithAttributeValue(LdapObjectCollection $groups, $attribute, $value)
    {
        $value = strtolower($value);

        /** @var LdapObject $group */
        foreach ($groups as $group) {
            if ($group->has($attribute) && strtolower($group->get($attribute)) == $value) {
                return true;
            }
        }

        return false;
    }

    /**
     * @param LdapUserInterface $user
     * @return LdapObjectCollection
     */
    protected function getGroupsForUser(LdapUserInterface $user)
    {
        $select = $this->roleAttrMap;
        unset($select['members']);

        $query = $this->ldap->buildLdapQuery()
            ->from($this->groupObjectType)
            ->select(array_values($select));
        /**
         * @todo How to support recursive group checks for all LDAP types? Need a recursive method check of sorts...
         */
        if ($this->ldap->getConnection()->getConfig()->getLdapType() === LdapConnection::TYPE_AD && $this->checkGroupsRecursively) {
            $query->where($query->filter()->hasMemberRecursively($user->getLdapGuid(), $this->roleAttrMap['members']));
        } else {
            $query->where([$this->roleAttrMap['members'] => $user->getLdapGuid()]);
        }
        
        return $query->getLdapQuery()->getResult();
    }

    /**
     * @param LdapObject $ldapObject
     * @return LdapUserInterface
     */
    protected function constructUserClass(LdapObject $ldapObject)
    {
        $errorMessage = 'Unable to instantiate user class "%s". Error was: %s';

        try {
            /** @var LdapUserInterface $user */
            $user = new $this->userClass();
            $user->setUsername($ldapObject->get('username'));
            $user->setLdapGuid($ldapObject->get('guid'));
        } catch (\Throwable $e) {
            throw new UnsupportedUserException(sprintf($errorMessage, $this->userClass, $e->getMessage()));
        // Unlikely to help much in PHP 5.6, but oh well...
        } catch (\Exception $e) {
            throw new UnsupportedUserException(sprintf($errorMessage, $this->userClass, $e->getMessage()));
        }
        // If the class also happens to extends the LdapTools LdapObject class, then set the attributes and type...
        if ($user instanceof LdapObject) {
            $user->setBatchCollection(new BatchCollection($ldapObject->get('dn')));
            $user->refresh($ldapObject->toArray());
            // This is to avoid the constructor
            $refObject = new \ReflectionObject($user);
            $refProperty = $refObject->getProperty('type');
            $refProperty->setAccessible(true);
            $refProperty->setValue($user, $this->ldapObjectType);
        }

        return $user;
    }
}
