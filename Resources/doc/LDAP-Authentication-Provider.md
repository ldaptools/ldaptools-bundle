LDAP Authentication Provider
================

Setting up LDAP form based authentication can be done easily with the following security config example:

```yaml
# app/config/security.yml
security:
    # ...
    providers:
        ldap:
            id: ldap_tools.security.user.ldap_user_provider

    firewalls:
        restricted_area:
            pattern: ^/admin
            logout:
                path:   logout
                target: login
            ldap_tools_form:
               check_path: login_check
               login_path: login
```

The LDAP provider is used for the purpose of this example, but any other user provider can be substituted. By default the
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
