LDAP Authentication Provider
================

  * [Symfony 2.8+](#symfony-28-use-the-guard-component)
  * [Symfony 2.3](#symfony-23-use-ldap_tools_form-custom-authentication-type)
  * [LDAP Authentication Username](#ldap-authentication-username)
  * [Mapping LDAP Groups to Roles](#mapping-ldap-groups-to-roles)
  * [Mapping LDAP Attributes](#mapping-ldap-attributes)
  * [Guard Specific Settings](#guard-specific-settings)
  * [Guard Redirection](#guard-redirection)
  * [Show Detailed Login Errors](#hideshow-detailed-login-errors)
  * [LDAP Login Event](#successful-login-event)
  * [Load User Events](#load-user-events)
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

## LDAP Authentication Username

By default when you configure the authentication to use LDAP it will use the provided username from `getUsername()` of
the user from the UserProvider to bind to LDAP. In the case of Active Directory this will work fine with no modification
needed. However, OpenLDAP and other LDAPs may require a full DN for login.

To get around the above you can define a `bind_format` option in LdapTools to form a full DN for the bind. An example of
this would be:

```yaml
ldap_tools:
    domains:
        example:
            # The simple name of the user will replace the %%username%%
            # Double %% needed to escape the normal parameter resolution in Symfony
            bind_format: "CN=%%username%%,CN=Users,DC=example,DC=local"
```

Now when you authenticate a user a full DN will be formed using the above string.

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

## Mapping LDAP Attributes

By default this bundle uses the LdapTools `user` schema type when loading LDAP users. It needs the `username` and `guid`
attribute mappings of that user type for the user's username and GUID. By default the LdapTools `user` schema type has
mappings for these for both Active Directory and OpenLDAP. If you have more specific requirements you can extend the
default user type and provide your own mappings.

For instance, lets assume you are using Active Directory but want to force users to use their UPN for their username.
You can do this as follows:

1. Create a new file: `app/Resources/schema/ad.yml`.

2. In the new schema file put in the following:

```yaml
# Extends the default 'ad' schema for LdapTools
extends_default: ad
objects:
    # Create a special 'LoginUser' type extending the default...
    login_user:
        extends_default: [ 'ad', 'user' ]
        type: 'SymfonyUser'
        attributes:
            username: userPrincipalName
```

3. Configure the bundle to use your custom schema and user type for the login.

```yaml
# app/config/config.yml
ldap_tools:
    general:
        schema_folder: "%kernel.root_dir%/Resources/schema"
    security:
        ldap_object_type: 'SymfonyUser'
```

For a complete listing of possible directives you can use for a custom schema type see the [LdapTools docs](https://github.com/ldaptools/ldaptools/blob/master/docs/en/reference/Schema-Configuration.md#schema-object-configuration-options).

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
            default_target_path: '/'
            always_use_target_path: false
            target_path_parameter: '_target_path'
            use_referrer: false
            failure_path: null
            failure_forward: false
            failure_path_parameter: '_failure_path'
            remember_me: false
```

## Guard Redirection

Due to the way the Guard is currently designed in Symfony, the redirection settings are handled through config options 
here. While this does not allow for firewall specific redirection settings, you can get more fine-grained by hooking into
events.

On authentication success the Guard will trigger the event `ldap_tools_bundle.login.handler.success`. You can inspect the
request, firewall provider name, token, etc and then use the `setResponse()` method of the event to control the redirect.
You can do the same thing for failures in the `ldap_tools_bundle.login.handler.failure` event.

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
 
```php
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

## Load User Events

Before and after a user is loaded from the user provider by their username a `ldap_tools_bundle.user_load.before` event
and `ldap_tools_bundle.user_load.after` is called (respectively). You can call the `getUsername()` or `getDomain()` method 
of the before or after event. For the after event you can call `getUser()` to get the user instance that was loaded, and
you can use the `getLdapObject()` method to get the LDAP object that the user was loaded from. This is most useful when 
using a separate bundle for the user provider, such as the FOSUserBundle, and gives you more fine-grained control over 
the process.
 
#### 1. Create the event listener class.
 
```php
namespace AppBundle\Event;

use LdapTools\Bundle\LdapToolsBundle\Event\LoadUserEvent;

class LoadUserListener
{
    public function beforeLoadUser(LoadUserEvent $event)
    {
        // Get the username to be loaded...
        $username = $event->getUsername();
        // Get the domain for the username...
        $domain = $event->getDomain();
        
        // Do something with the username/domain before it hits the user provider...
    }
    
    public function afterLoadUser(LoadUserEvent $event)
    {
        // Get the username that was loaded...
        $username = $event->getUsername();
        // Get the domain for the username...
        $domain = $event->getDomain();
        // Get the actual user instance...
        $user = $event->getUser();
        // Get the LDAP object the user was loaded from...
        $ldapObject = $event->getLdapObject();
        
        // Do something with the user/username/domain/LDAP attributes before it is authenticated...
        foreach($ldapObject->toArray() as $attribute => $value) {
            # ...
        }
    }
}
```

#### 2. Create and tag the above class as a service.

```yaml
# app/config/services.yml
    app.event.login_listener:
        class: AppBundle\Event\LoadUserListener
        tags:
            - { name: kernel.event_listener, event: ldap_tools_bundle.load_user.before, method: beforeLoadUser }
            - { name: kernel.event_listener, event: ldap_tools_bundle.load_user.after, method: afterLoadUser }
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
