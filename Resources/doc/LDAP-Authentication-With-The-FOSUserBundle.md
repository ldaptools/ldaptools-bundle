LDAP Authentication with the FOSUserBundle
==========

There may be times where you want to have a custom User class that gets loaded from a database (such as FOSUserBundle)
but then authenticate that user against LDAP on login. This can be accomplished easily when using this bundle's LDAP
guard component.

#### 1. Follow the [FOSUserBundle Getting Started Guide](https://symfony.com/doc/master/bundles/FOSUserBundle/index.html).

Follow the above guide like you normally would to get your database user ready/created.

#### 2. Follow the [LDAP Authentication Provider](./LDAP-Authentication-Provider.md) steps to setup the Guard.

**Note:** This is for Symfony 2.8+ only, as we are using the Guard component.
 
#### 3. Setup your user provider to use the FOSUserBundle user provider.

Your end security config using the FOSUserBundle provider, but the LDAP authentication Guard, would look like:

```yml
security:

    hide_user_not_found: false

    encoders:
        FOS\UserBundle\Model\UserInterface: bcrypt

    providers:
        fos_userbundle:
            id: fos_user.user_provider.username

    firewalls:
        dev:
            pattern: ^/(_(profiler|wdt)|css|images|js)/
            security: false

        main:
            anonymous: ~
            # Using the FOSUserBundle provider to find the users...
            provider: fos_userbundle
            form_login:
                login_path: login
                check_path: login_check
                use_forward: true
            pattern: ^/
            logout: ~
            # Using the LDAP Guard to authenticate the users...
            guard:
                authenticators:
                    - ldap_tools.security.ldap_guard_authenticator
        login:
            pattern: ^/login$
            anonymous: ~

    access_control:
        - { path: ^/login, roles: IS_AUTHENTICATED_ANONYMOUSLY }
        - { path: ^/, roles: ROLE_USER }
```

4. Create FOSUserBundle Users and Roles

Note that with the above you're still responsible for creating users within the FOSUserBundle so they exist in the database.
However, the user's can have any password (or none at all) as the authentication is done against LDAP and not against their
password stored in the database.

You should also note that LDAP role mapping for the LdapTools config will not take effect. That's a function of the LDAP
user provider in this bundle. However, you can hook into the `ldap_tools_bundle.login.success` event and assign any roles
based on an LDAP query there. For an example see the [LDAP authentication provider doc](./LDAP-Authentication-Provider.md#Successful-Login-Event).
