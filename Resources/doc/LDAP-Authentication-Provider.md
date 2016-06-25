LDAP Authentication Provider
================

Setting up LDAP form based authentication can be done fairly easily. Simply following the example configs listed below
depending on your Symfony version. For Symfony 2.8+ the Guard component is used. In each example, don't forget to 
register the needed routes (`login`, `login_check`) along with other boiler-plate code (the controller login action and 
the login
form).

The following example security configs secure your full site with a LDAP form login: 

### Symfony 2.8+ (Use the Guard Component)

```yaml
# app/config/security.yml
security:

    encoders:
            LdapTools\Bundle\LdapToolsBundle\Security\User\LdapUser: plaintext

    providers:
        ldap:
            id: ldap_tools.security.user.ldap_user_provider

    firewalls:
        # disables authentication for assets and the profiler, adapt it according to your needs
        dev:
            pattern: ^/(_(profiler|wdt)|css|images|js)/
            security: false

        main:
            anonymous: ~
            provider: ldap
            form_login:
                login_path: login
                check_path: login_check
                use_forward: true
            pattern: ^/
            logout: ~
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

### Symfony 2.3 (Use ldap_tools_form custom authentication type)

```yaml
# app/config/security.yml
security:

    encoders:
            LdapTools\Bundle\LdapToolsBundle\Security\User\LdapUser: plaintext

    providers:
        ldap:
            id: ldap_tools.security.user.ldap_user_provider

    firewalls:
        # disables authentication for assets and the profiler, adapt it according to your needs
        dev:
            pattern: ^/(_(profiler|wdt)|css|images|js)/
            security: false

        main:
            anonymous: ~
            provider: ldap
            pattern: ^/
            logout: ~
            ldap_tools_form:
               check_path: login_check
               login_path: login

        login:
            pattern: ^/login$
            anonymous: ~

    access_control:
        - { path: ^/login, roles: IS_AUTHENTICATED_ANONYMOUSLY }
        - { path: ^/, roles: ROLE_USER }
```

The LDAP provider is used for the purpose of these examples, but other user providers can be substituted. By default the
LDAP user provider provides an extended instance of `\LdapTools\Object\LdapObject`.

## Mapping LDAP Groups to Roles

Mapping LDAP groups to specific roles can be done via the bundle configuration:

```yaml
# app/config/config.yml
# ...
ldap_tools:
    security:
        roles:
            SUPER_ADMIN: [ 'Domain Admins' ]
```

The above would grant any user that is a member of the `Domain Admins` LDAP group the `SUPER_ADMIN` role in Symfony. You
can specify any number of LDAP group names for a specific role. Group membership is checked recursively by default for
Active Directory.

By default the `ROLE_USER` is assigned to any LDAP user that successfully authenticates. The change this behavior you
can modify the bundle config:

```yaml
# app/config/config.yml
# ...
ldap_tools:
    security:
        # Set to null for no role to be assigned by default. Or set it to another role altogether.
        default_role: ROLE_APP_USER
```

## Guard Specific Settings

There are some guard specific settings you can configure on the `app/config.yml` file:

```yaml
# app/config/config.yml
# ...
ldap_tools:
    security:
        guard:
            # This is the entry point/start path route name for the RedirectResponse of the Guard component
            start_path: 'login'
```
