LDAP Authentication Provider
================

  * [Symfony 2.8+](#symfony-28-use-the-guard-component)
  * [Symfony 2.3](#symfony-23-use-ldap_tools_form-custom-authentication-type)
  * [Mapping LDAP Groups to Roles](#mapping-ldap-groups-to-roles)
  * [Guard Specific Settings](#guard-specific-settings)
  * [Show Detailed Login Errors](#hideshow-detailed-login-errors)
  * [LDAP Login Event](#successful-login-event)
  * [User Refresh Settings](#user-refresh-settings)
  * [Multiple Domain Login](#multiple-domain-login)

Setting up LDAP form based authentication can be done fairly easily. Simply follow the example configs listed below
depending on your Symfony version. For Symfony 2.8+ the Guard component is used. In each example, don't forget to 
register the needed routes (`login`, `login_check`) along with other boiler-plate code (the controller login action and 
the login form).

The following example security configs secure your full site with a LDAP form login: 

### Symfony 2.8+ (Use the Guard Component)

```yaml
# app/config/security.yml
security:

    encoders:
        # This is the default user class returned from the LDAP provider below
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
            # Use the default LDAP user provider defined above
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
        # This is the default user class returned from the LDAP provider below
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
            # Use the default LDAP user provider defined above
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

Mapping LDAP groups to specific roles can be done via the bundle configuration. The groups can be mapped using their 
common name, GUID, SID, or full DN:

```yaml
# app/config/config.yml
# ...
ldap_tools:
    security:
        roles:
            # Using the common group name
            SUPER_ADMIN: [ 'Domain Admins' ]
            # Using the distinguished name of the group
            ROLE_APP_USER: 'CN=App Users,OU=Groups,DC=example,DC=local'
            # Using the GUID or SID of a group
            ROLE_APP_ADMINS: ['291d8444-9d5b-4b0a-a6d7-853408f704d5', 'S-1-5-21-917267712-1342860078-1792151419-500']
```

The above would grant any user that is a member of the `Domain Admins` LDAP group the `SUPER_ADMIN` role in Symfony. You
can specify any number of LDAP group names for a specific role. Group membership is checked recursively by default for
Active Directory. You can also mix DNs, SIDs, GUIDs, and names mapped to a specific role.

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

## Hide/Show Detailed Login Errors

By default errors as to why authentication may have failed are hidden and just shown as "Bad Credentials". To get it to
show more information you can set the `hide_user_not_found` security configuration to `false`. This is under the main
Symfony security configuration:

```yaml
# app/config/security.yml

security:
    hide_user_not_found:  false

    # ...
```

## Successful Login Event

After a successful LDAP authentication attempt by the authentication provider a `ldap_tools_bundle.login.success` event
is dispatched. You can call the `getUser()` method of the event to get the LDAP user that was just authenticated. You
can then add/remove roles or do anything else you like before their token is created and their roles solidified. You
can also call the `getToken()` method to get the credentials used in the attempt. A quick example:

#### 1. Create the event listener class.
 
```
namespace AppBundle\Event;

use LdapTools\Bundle\LdapToolsBundle\Event\LdapLoginEvent;

class LdapLoginListener
{
    public function onLdapLoginSuccess(LdapLoginEvent $event)
    {
        // Get the LDAP user that logged in...
        $user = $event->getUser();
        // Get the credentials they used for the login...
        $password = $event->getToken()->getCredentials();
        
        // Do something with the user/password combo...
    }
}
```

#### 2. Create and tag the above class as a service.

```yaml
# app/config/services.yml
    app.event.login_listener:
        class: AppBundle\Event\LdapLoginListener
        tags:
            - { name: kernel.event_listener, event: ldap_tools_bundle.login.success, method: onLdapLoginSuccess }
```

## User Refresh Settings

When Symfony processes a request it will attempt to "refresh" the authenticated user using your user provider. If you are
using this bundles LDAP user provider, it will not refresh the user by default to reduce the amount of LDAP queries
against your LDAP server. This means if you want the app to re-query LDAP for your user and any roles associated with 
them on each request you have to change some settings:

Both of these settings are set to `false` by default:

```yaml
# app/config/config.yml

ldap_tools:
    security:
        # Set this to true if you want user attributes re-queried on each request.
        refresh_user_attributes: true
        # Set this to true if you want user roles re-queried on each request.
        refresh_user_roles: true

    # ...
```

Having both of these set to true by default means no LDAP queries will be performed for the user while they are still 
logged in. Any changes in LDAP (such as their account being renamed, disabled, locked, expired, etc) will not take effect
until they logout and log back into the web application. Any group membership changes that affect roles will not be 
noticed  after the initial login. To change this behavior modify the above settings as needed. However, this may
effect application performance and the load against your LDAP server depending on the size of your app.

## Multiple Domain Login

When you have multiple domains defined in your configuration, you may want to have users choose the domain they will
authenticate against on login. This can be done by defining a `<select>` element in your login form that contains a list
of options whose values are the FQDN of the domains in your config. This element must have an ID of `_ldap_domain`:

```html
<form action="{{ path('login') }}" method="post">
    <label for="username">Username:</label>
    <input type="text" id="username" name="_username" value="{{ last_username }}" />

    <label for="password">Password:</label>
    <input type="password" id="password" name="_password" />
    <label for="_ldap_domain">Domain:</label>
    <select id="_ldap_domain" name="_ldap_domain">
        <option value="example.local" selected="selected">Example</option>
        <option value="domain2.local">Domain 2</option>
    </select>

    <button type="submit">login</button>
</form>
```
