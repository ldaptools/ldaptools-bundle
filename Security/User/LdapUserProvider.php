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
     * @var array
     */
    protected $options = [
        'refresh_user_roles' => false,
        'refresh_user_attributes' => false,
        'search_base' => null,
        'ldap_object_type' => 'user',
        'user' => LdapUser::class,
        'additional_attributes' => [],
    ];

    /**
     * @param LdapManager $ldap
     * @param EventDispatcherInterface $dispatcher
     * @param LdapRoleMapper $roleMapper
     * @param array $options
     */
    public function __construct(LdapManager $ldap, EventDispatcherInterface $dispatcher, LdapRoleMapper $roleMapper, array $options)
    {
        $this->ldap = $ldap;
        $this->dispatcher = $dispatcher;
        $this->roleMapper = $roleMapper;
        $this->options = array_merge($this->options, $options);
    }

    /**
     * {@inheritdoc}
     */
    public function loadUserByUsername($username)
    {
        $this->dispatcher->dispatch(new LoadUserEvent($username, $this->ldap->getDomainContext()), LoadUserEvent::BEFORE);
        $ldapUser = $this->getLdapUser('username', $username);
        $user = $this->constructUserClass($ldapUser);
        $this->roleMapper->setRoles($user);
        $this->dispatcher->dispatch(new LoadUserEvent($username, $this->ldap->getDomainContext(), $user, $ldapUser), LoadUserEvent::AFTER);

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

        if ($this->options['refresh_user_attributes']) {
            $user = $this->constructUserClass($this->getLdapUser('guid', $user->getLdapGuid()));
        }
        if ($this->options['refresh_user_roles']) {
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
    public function getLdapUser($attribute, $value)
    {
        try {
            $query = $this->ldap->buildLdapQuery()
                ->select($this->getAttributesToSelect())
                ->from($this->options['ldap_object_type'])
                ->where([$attribute => $value]);
            if (!is_null($this->options['search_base'])) {
                $query->setBaseDn($this->options['search_base']);
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
            $this->options['additional_attributes']
        ))));
    }

    /**
     * @param LdapObject $ldapObject
     * @return LdapUserInterface
     */
    protected function constructUserClass(LdapObject $ldapObject)
    {
        if (!$this->supportsClass($this->options['user'])) {
            throw new UnsupportedUserException(sprintf(
                'The LDAP user provider class "%s" must implement "%s".',
                $this->options['user'],
                LdapUserInterface::class
            ));
        }

        $errorMessage = 'Unable to instantiate user class "%s". Error was: %s';
        try {
            /** @var LdapUserInterface $user */
            $user = new $this->options['user']();
            $user->setUsername($ldapObject->get('username'));
            $user->setLdapGuid($ldapObject->get('guid'));
        } catch (\Throwable $e) {
            throw new UnsupportedUserException(sprintf($errorMessage, $this->options['user'], $e->getMessage()));
        // Unlikely to help much in PHP 5.6, but oh well...
        } catch (\Exception $e) {
            throw new UnsupportedUserException(sprintf($errorMessage, $this->options['user'], $e->getMessage()));
        }
        // If the class also happens to extend the LdapTools LdapObject class, then set the attributes and type...
        if ($user instanceof LdapObject) {
            $this->hydrateLdapObjectUser($ldapObject, $user);
        }

        return $user;
    }

    /**
     * @param LdapObject $ldapObject
     * @param $user
     */
    protected function hydrateLdapObjectUser(LdapObject $ldapObject, LdapObject $user)
    {
        $user->setBatchCollection(new BatchCollection($ldapObject->get('dn')));
        $user->refresh($ldapObject->toArray());

        // This is to avoid the constructor
        $refObject = new \ReflectionObject($user);
        $refProperty = $refObject->getProperty('type');
        $refProperty->setAccessible(true);
        $refProperty->setValue($user, $this->options['ldap_object_type']);
    }
}
