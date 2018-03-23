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
use LdapTools\LdapManager;
use LdapTools\Object\LdapObjectCollection;
use LdapTools\Utilities\LdapUtilities;

/**
 * Maps LDAP groups to Symfony Roles for a LdapUserInterface user.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class LdapRoleMapper
{
    /**
     * @var LdapManager
     */
    protected $ldap;

    /**
     * @var array
     */
    protected $options = [
        'check_groups_recursively' => true,
        'default_role' => 'ROLE_USER',
        'roles' => [],
        'role_ldap_type' => 'group',
        'role_attributes' => [
            'guid' => 'guid',
            'sid' => 'sid',
            'name' => 'name',
            'members' => 'members',
        ],
    ];

    /**
     * @param LdapManager $ldap
     * @param array $options
     */
    public function __construct(LdapManager $ldap, array $options)
    {
        $this->ldap = $ldap;
        $this->options = array_merge($this->options, $options);
    }

    /**
     * Set the roles for the user based on LDAP group membership.
     *
     * @param LdapUserInterface $user
     * @return LdapUserInterface
     */
    public function setRoles(LdapUserInterface $user)
    {
        $roles = [];

        if ($this->options['default_role']) {
            $roles[] = $this->options['default_role'];
        }
        
        if (!empty($this->options['roles'])) {
            $groups = $this->getGroupsForUser($user);

            foreach ($this->options['roles'] as $role => $roleGroups) {
                if ($this->hasGroupForRoles($roleGroups, $groups)) {
                    $roles[] = $role;
                }
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
                $attribute = $this->options['role_attributes']['guid'];
            } elseif (preg_match(LdapUtilities::MATCH_SID, $roleGroup)) {
                $attribute = $this->options['role_attributes']['sid'];
            } else {
                $attribute = $this->options['role_attributes']['name'];
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

        /** @var \LdapTools\Object\LdapObject $group */
        foreach ($groups as $group) {
            if ($group->has($attribute) && strtolower($group->get($attribute)) === $value) {
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
        $select = $this->options['role_attributes'];
        unset($select['members']);

        $query = $this->ldap->buildLdapQuery()
            ->from($this->options['role_ldap_type'])
            ->select(array_values($select));

        /**
         * @todo How to support recursive group checks for all LDAP types? Need a recursive method check of sorts...
         */
        if ($this->ldap->getConnection()->getConfig()->getLdapType() === LdapConnection::TYPE_AD && $this->options['check_groups_recursively']) {
            $query->where($query->filter()->hasMemberRecursively($user->getLdapGuid(), $this->options['role_attributes']['members']));
        } else {
            $query->where([$this->options['role_attributes']['members'] => $user->getLdapGuid()]);
        }

        return $query->getLdapQuery()->getResult();
    }
}
