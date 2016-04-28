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

use LdapTools\Object\LdapObject;
use Symfony\Component\Security\Core\User\AdvancedUserInterface;

/**
 * Represents a user from LDAP.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class LdapUser extends LdapObject implements AdvancedUserInterface, \Serializable
{
    /**
     * @var array The Symfony roles for this user.
     */
    protected $roles = [];

    /**
     * @var string The attribute that the username is mapped to.
     */
    protected $attrMap = [
        'username' => 'username',
        'accountNonLocked' => 'locked',
        'accountNonExpired' => 'accountExpirationDate',
        'enabled' => 'disabled',
        'credentialsNonExpired' => 'passwordMustChange',
        'guid' => 'guid',
        'groups' => 'groups',
        'stringRepresentation' => 'username',
    ];

    /**
     * @param LdapObject $ldapObject
     * @param array $attrMap
     */
    public function __construct(LdapObject $ldapObject, array $attrMap = [])
    {
        if (!empty($attrMap)) {
            $this->attrMap = array_merge($this->attrMap, $attrMap);
        }
        parent::__construct(...$this->getParentArgs($ldapObject));
    }

    /**
     * {@inheritdoc}
     */
    public function getSalt()
    {
        return null;
    }

    /**
     * {@inheritdoc}
     */
    public function getPassword()
    {
        return null;
    }

    /**
     * {@inheritdoc}
     */
    public function eraseCredentials()
    {
        return null;
    }

    /**
     * {@inheritdoc}
     */
    public function getRoles()
    {
        return $this->roles;
    }

    /**
     * {@inheritdoc}
     */
    public function setRoles(array $roles)
    {
        $this->roles = [];
        foreach ($roles as $role) {
            $this->addRole($role);
        }

        return $this;
    }

    /**
     * {@inheritdoc}
     */
    public function addRole($role)
    {
        $role = strtoupper($role);

        if (!in_array($role, $this->roles)) {
            $this->roles[] = $role;
        }

        return $this;
    }

    /**
     * {@inheritdoc}
     */
    public function removeRole($role)
    {
        $role = strtoupper($role);

        if (in_array($role, $this->roles)) {
            $this->roles = array_diff($this->roles, [$role]);
        }

        return $this;
    }

    /**
     * {@inheritdoc}
     */
    public function getUsername()
    {
        return $this->get($this->attrMap['username']);
    }

    /**
     * {@inheritdoc}
     */
    public function setUsername($username)
    {
        return $this->set($this->attrMap['username'], $username);
    }

    /**
     * {@inheritdoc}
     */
    public function isAccountNonExpired()
    {
        if (!$this->has($this->attrMap['accountNonExpired']) || $this->get($this->attrMap['accountNonExpired']) === false) {
            $result = true;
        } elseif ($this->get($this->attrMap['accountNonExpired']) instanceof \DateTime) {
            $result = ($this->get($this->attrMap['accountNonExpired']) > new \DateTime());
        } else {
            $result = (bool) $this->get($this->attrMap['accountNonExpired']);
        }

        return $result;
    }

    /**
     * {@inheritdoc}
     */
    public function isAccountNonLocked()
    {
        return $this->has($this->attrMap['accountNonLocked']) ? !$this->get($this->attrMap['accountNonLocked']) : true;
    }

    /**
     * {@inheritdoc}
     */
    public function isCredentialsNonExpired()
    {
        return $this->has($this->attrMap['credentialsNonExpired']) ?
            !$this->get($this->attrMap['credentialsNonExpired']) : true;
    }

    /**
     * {@inheritdoc}
     */
    public function isEnabled()
    {
        return $this->has($this->attrMap['enabled']) ? !$this->get($this->attrMap['enabled']) : true;
    }

    /**
     * {@inheritdoc}
     */
    public function getLdapGuid()
    {
        return $this->get($this->attrMap['guid']);
    }

    /**
     * {@inheritdoc}
     */
    public function getGroups()
    {
        return $this->get($this->attrMap['groups']);
    }

    /**
     * {@inheritdoc}
     */
    public function serialize()
    {
        return serialize([
            $this->attributes,
            $this->category,
            $this->class,
            $this->attrMap,
        ]);
    }

    /**
     * {@inheritdoc}
     */
    public function unserialize($serialized)
    {
        list(
            $this->attributes,
            $this->category,
            $this->class,
            $this->attrMap
            ) = unserialize($serialized);
    }

    /**
     * @return string
     */
    public function __toString()
    {
        return (string) $this->get($this->attrMap['stringRepresentation']);
    }

    /**
     * Temporary BC method for LdapObject construction.
     * 
     * @todo remove this at some point. This is to check for instances where the class/category was in the constructor.
     * @param LdapObject $ldapObject
     * @return array
     */
    protected function getParentArgs(LdapObject $ldapObject)
    {
        $constructor = (new \ReflectionClass(get_parent_class()))->getConstructor();
        
        if ($constructor->getNumberOfParameters() == 2) {
            $args = [$ldapObject->toArray(), $ldapObject->getType()];
        } else {
            $args = [$ldapObject->toArray(), [], '', $ldapObject->getType()];
        }
        
        return $args;
    }
}
