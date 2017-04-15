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
use LdapTools\Exception\EmptyResultException;
use LdapTools\Exception\MultiResultException;
use LdapTools\LdapManager;
use LdapTools\Object\LdapObject;
use LdapTools\Object\LdapObjectType;
use Symfony\Component\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\Security\Core\Exception\UnsupportedUserException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Core\Exception\UsernameNotFoundException;

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
     * @var LdapRoleMapper
     */
    protected $roleMapper;

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
     * @var string The object type to search LDAP for.
     */
    protected $ldapObjectType = LdapObjectType::USER;
    
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
     * @param LdapRoleMapper $roleMapper
     */
    public function __construct(LdapManager $ldap, EventDispatcherInterface $dispatcher, LdapRoleMapper $roleMapper)
    {
        $this->ldap = $ldap;
        $this->dispatcher = $dispatcher;
        $this->roleMapper = $roleMapper;
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
        $user = $this->constructUserClass($ldapUser);
        $this->roleMapper->setRoles($user);
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
            $this->roleMapper->setRoles($user);
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
