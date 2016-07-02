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

use LdapTools\Exception\EmptyResultException;
use LdapTools\Exception\MultiResultException;
use LdapTools\Object\LdapObject;
use LdapTools\Object\LdapObjectCollection;
use LdapTools\Object\LdapObjectType;
use LdapTools\Utilities\LdapUtilities;
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
     * @var array Map names to their LDAP attribute names when querying for LDAP groups used for roles.
     */
    protected $roleAttrMap = [
        'name' => 'name',
        'sid' => 'sid',
        'guid' => 'guid',
        'members' => 'members',
    ];

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
     * @var string The group object type when searching group membership.
     */
    protected $groupObjectType = LdapObjectType::GROUP;
    
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
        $this->setRolesForUser($user);

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
     */
    protected function setRolesForUser(LdapUser $user)
    {
        if ($this->defaultRole) {
            $user->addRole($this->defaultRole);
        }
        $groups = $this->getGroupsForUser($user);

        foreach ($this->roleMap as $role => $roleGroups) {
            if ($this->hasGroupForRoles($roleGroups, $groups)) {
                $user->addRole($role);
            }
        }
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
     * @param LdapUser $user
     * @return LdapObjectCollection
     */
    protected function getGroupsForUser(LdapUser $user)
    {
        $select = $this->roleAttrMap;
        unset($select['members']);

        $query = $this->ldap->buildLdapQuery()
            ->from($this->groupObjectType)
            ->select(array_values($select));
        
        if ($this->checkGroupsRecursively) {
            $query->where($query->filter()->hasMemberRecursively($user->getLdapGuid(), $this->roleAttrMap['members']));
        } else {
            $query->where([$this->roleAttrMap['members'] => $user->getLdapGuid()]);
        }
        
        return $query->getLdapQuery()->getResult();
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
