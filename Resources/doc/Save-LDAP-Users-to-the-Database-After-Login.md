Save LDAP Users to the Database After Login
==========

Often times you may want to save your LDAP user to a database after they login. This allows more flexibility than using
just the standard LdapUser of this bundle on login. To do this there are a few steps you have to follow. These steps are
designed around a standard Doctrine entity:

* [Create your Database User](#create-your-database-user) 
* [Create your User Provider Chain for LDAP and Doctrine](#create-your-user-provider-chain)
* [Configure your Firewall](#configure-your-firewall-for-the-guard)
* [Create a LDAP Login Success Event](#create-an-event-to-save-your-user-to-the-db-on-login)

## Create your Database User

Your database user should be a typical Doctrine entity. However, it will need to implement an interface:

* `LdapTools\Bundle\LdapToolsBundle\Security\User\LdapUserInterface`

Your basic app user will look something like:

```php
# src/AppBundle/Entity/AppUser.php

namespace AppBundle\Entity;

use Doctrine\ORM\Mapping as ORM;
use LdapTools\Bundle\LdapToolsBundle\Security\User\LdapUserInterface;
use Symfony\Component\Security\Core\User\UserInterface;

/**
 * @ORM\Entity
 * @ORM\Table(name="app_user")
 */
class AppUser implements LdapUserInterface, UserInterface
{
    /**
     * @ORM\Column(type="integer")
     * @ORM\Id
     * @ORM\GeneratedValue(strategy="AUTO")
     */
    private $id;

    /**
     * @ORM\Column(type="string", length=100)
     */
    private $ldapGuid;

    /**
     * @ORM\Column(type="text")
     */
    private $username;

    /**
     * @var array
     */
    private $roles = [];
    
    /**
     * Get id
     *
     * @return integer
     */
    public function getId()
    {
        return $this->id;
    }

    /**
     * Set ldapGuid
     *
     * @param string $ldapGuid
     *
     * @return AppUser
     */
    public function setLdapGuid($ldapGuid)
    {
        $this->ldapGuid = $ldapGuid;

        return $this;
    }

    /**
     * Get ldapGuid
     *
     * @return string
     */
    public function getLdapGuid()
    {
        return $this->ldapGuid;
    }

    /**
     * Set username
     *
     * @param string $username
     *
     * @return AppUser
     */
    public function setUsername($username)
    {
        $this->username = $username;

        return $this;
    }

    /**
     * Get username
     *
     * @return string
     */
    public function getUsername()
    {
        return $this->username;
    }

    public function eraseCredentials()
    {
    }

    /**
     * @param array $roles
     * @return $this
     */
    public function setRoles(array $roles)
    {
        $this->roles = $roles;

        return $this;
    }

    /**
     * @return array
     */
    public function getRoles()
    {
        return $this->roles;
    }

    /**
     * @return null
     */
    public function getPassword()
    {
        return null;
    }

    /**
     * @return null
     */
    public function getSalt()
    {
        return null;
    }
}
```

Set the encoder for the user to just simple plain text:

```yaml
# app/config/security.yml

    encoders:
        AppBundle\Entity\AppUser: plaintext
```

Note that in this example the password is not stored on the database user.

## Create your User Provider Chain
 
You must now chain your user providers (Both LDAP and the Doctrine entity user providers). This way it will try to load
a user from the database first and fallback to LDAP if they are not found in the database. Your chain would look like:

```yaml
# app/config/security.yml
    providers:
        chain_provider:
            chain:
                providers: [user_db, ldap]
        ldap:
            id: ldap_tools.security.user.ldap_user_provider
        user_db:
            entity: { class: AppBundle\Entity\AppUser, property: username }
```

## Configure your Firewall for the Guard

You'll need to tell your firewall to use the the LDAP Guard for authentication (as well as the new chained provider above).
Your firewall section should look similar to this:

```yaml
# app/config/security.yml
    firewalls:
        # disables authentication for assets and the profiler, adapt it according to your needs
        dev:
            pattern: ^/(_(profiler|wdt)|css|images|js)/
            security: false

        main:
            anonymous: ~
            # Here we use the chained provider defined previously...
            provider: chain_provider
            pattern: ^/
            logout: ~
            # Here we tell it to use the LDAP Guard for authentication...
            guard:
                authenticators:
                    - ldap_tools.security.ldap_guard_authenticator

        login:
            pattern: ^/login$
            anonymous: ~
```

Also make sure to set your access control properly. It should look something like this:

```yaml
# app/config/security.yml

    access_control:
        - { path: ^/translations$, role: IS_AUTHENTICATED_ANONYMOUSLY }
        - { path: ^/login, roles: IS_AUTHENTICATED_ANONYMOUSLY }
        - { path: ^/, roles: ROLE_USER }
```

## Create an Event to Save your User to the DB on Login

To save your user to the database after login (only if they haven't been already) we will hook into an event. So first
create your event listener class:

```php
# src/AppBundle/Event/LoginEventListener

namespace AppBundle\Event;

use AppBundle\Entity\AppUser;
use Doctrine\ORM\EntityManagerInterface;
use LdapTools\Bundle\LdapToolsBundle\Event\LdapLoginEvent;

class LoginEventListener
{
    /**
     * @var EntityManagerInterface
     */
    protected $em;

    /**
     * @param SessionInterface $session
     */
    public function __construct(EntityManagerInterface $em)
    {
        $this->em = $em;
    }

    /**
     * @param LdapLoginEvent $event
     */
    public function onLoginSuccess(LdapLoginEvent $event)
    {
        /** @var AppUser $user */
        $user = $event->getUser();

        // If the ID doesn't exist, then it hasn't been saved to the database. So save it..
        if (!$user->getId()) {
            $this->em->persist($user);
            $this->em->flush();
        }
        
        // The credentials on login are also available if needed...
        $password = $event->getToken()->getCredentials();
        
        // ...
    }
}
```

Register your created listener as a service and tag it with the `ldap_tools_bundle.login.success` event using the kernel
event listener:

```yaml
# src/AppBundle/Resource/config/services.yml

services:
    app_bundle.event.login_listener:
        class: AppBundle\Event\LoginEventListener
        arguments: ['@doctrine.orm.entity_manager']
        tags:
            - { name: kernel.event_listener, event: ldap_tools_bundle.login.success, method: onLoginSuccess }
```

Now every time someone logs in it will first attempt to load the user from the database. If they do not exist it will
search LDAP for the user. Then the user will get passed to the LDAP Guard authenticator where the credentials are validated
against LDAP. If they login successfully, and the user has not yet been saved to the database, then the user will also be
saved back to the database.
