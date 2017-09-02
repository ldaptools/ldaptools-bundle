Configuration Reference
================

* [General](#general)
* [Security](#security)
* [Guard](#guard)
* [Doctrine](#doctrine)
* [LdapTools](#ldaptools)

## General

All of these options fall underneath the main `ldap_tools` section.

 ------------------
#### logging

Whether or not LDAP operations should be logged.

**Default**: `false` (in the dev environment it is enabled by default)

 ------------------
#### profiling

Whether or not profiling data should be captured.

**Default**: `false` (in the dev environment it is enabled by default)

## Security

There are several options to control security. All of these are under the `security` section.

 ------------------
#### login_query_attribute

When authenticating a username in the authentication providers, this attribute can be specified to query the username
value against to retrieve a DN of the username. The DN is needed for authentication in OpenLDAP, where as in AD a username
will typically work fine.

If you are using the LdapUserProvider provided by this bundle you should not have to set this. But if you're using a
different user provider, or your own defined LDAP User class, then you might have to.

**Default**: `null`

 ------------------
#### search_base

The default DN to start the user search from when loading users from the LdapUserProvider.

**Default**: Uses the LdapTools `base_dn` for the domain if not defined.

 ------------------
#### ldap_object_type

The default LdapTools object type to query for when loading users from the LdapUserProvider.

**Default**: `user`

 ------------------
#### default_role

The default role to assign users loaded from the LdapUserProvider. If you set this to null the the user will be loaded
from LDAP but not assigned any roles.

**Default**: `ROLE_USER`

 ------------------
#### check_groups_recursively

If set to true then group membership will contain all groups, and nested groups, the user belongs to. However, note that
this currently is only valid for Active Directory domains (not OpenLDAP).

**Default**: `true`

 ------------------
#### user

The user class that the LDAP user provider will instantiate. If you change this the class must implement `LdapUserInterface`.

**Default**: `LdapTools\Bundle\LdapToolsBundle\Security\User\LdapUser`

 ------------------
#### additional_attributes

Any additional attributes you would like selected when the user is loaded from the LdapUserProvider. You can access them
on the user object with the get method. ie: `$user->get('attribute');`.

**Default**: `null`

 ------------------
#### roles

Map LDAP groups to specific roles. The groups can be mapped using their common name, GUID, SID, or full DN:

```yaml
ldap_tools:
    security:
        roles:
            # Using the common group name...
            SUPER_ADMIN: 'Domain Admins'
            # Using the distinguished name of the group...
            ROLE_APP_USER: 'CN=App Users,OU=Groups,DC=example,DC=local'
            # Using the GUID or SID of a group...
            ROLE_APP_ADMINS:
                - '291d8444-9d5b-4b0a-a6d7-853408f704d5'
                - 'S-1-5-21-917267712-1342860078-1792151419-1211'
```

Group membership is checked recursively by default for Active Directory.

**Default**: `null`

 ------------------
#### role_ldap_type

The LdapTools object type for the groups used to check for roles.

**Default**: `group`

 ------------------
#### role_attributes

When searching for groups/roles for a user, map to these attributes for GUID, SID, members, or name. These can be any
valid LDAP attribute for a group or an attribute you have defined on your LdapTools schema object.

**Default**:

```yaml
ldap_tools:
    security:
        role_attributes:
            name: name
            sid: sid
            guid: guid
            members: members
```

 ------------------
#### refresh_user_attributes

Set this to true if you want user attributes re-queried on a user refresh from the LdapUserProvider.

**Default**: `false`

 ------------------
#### refresh_user_roles

Set this to true if you want user roles re-queried on a user refresh from the LdapUserProvider.

**Default**: `false`

## Guard

These are Guard specific security settings under the `security.guard` section.

 ------------------
#### http_basic

Whether or not the guard should be used for HTTP basic authentication.

**Default**: `false`

 ------------------
#### http_basic_domain

A specific domain name to use for HTTP basic authentication. If not set it will use the default domain for LdapTools.

**Default**: `null`

 ------------------
#### http_basic_realm

A specific realm for HTTP basic authentication prompt. If not set it will first use the `http_basic_domain` value if set.
If that is not set it will use the default domain name from LdapTools.

**Default**: `null`

 ------------------
#### login_path

Refer to: http://symfony.com/doc/current/reference/configuration/security.html#login-path

**Default**: `/login`

 ------------------
#### use_forward

Refer to: http://symfony.com/doc/current/reference/configuration/security.html#use-forward

**Default**: `false`

 ------------------
#### post_only

Refer to: http://symfony.com/doc/current/reference/configuration/security.html#post-only

**Default**: `false`

 ------------------
#### remember_me

Refer to: http://symfony.com/doc/current/reference/configuration/security.html#full-default-configuration

**Default**: `false`

 ------------------
#### username_parameter

Refer to: http://symfony.com/doc/current/reference/configuration/security.html#username-parameter

**Default**: `_username`

 ------------------
#### password_parameter

Refer to: http://symfony.com/doc/current/reference/configuration/security.html#password-parameter

**Default**: `_password`

 ------------------
#### domain_parameter

The domain name parameter for the LDAP domain to use during the login process. If this parameter is set during the login
it will attempt to authenticate the user against the domain specified for the parameters values.

**Default**: `_ldap_domain`

 ------------------
#### default_target_path

Refer to: http://symfony.com/doc/current/reference/configuration/security.html#redirecting-after-login

**Default**: `/`

 ------------------
#### always_use_target_path

Refer to: http://symfony.com/doc/current/reference/configuration/security.html#redirecting-after-login

**Default**: `false`

 ------------------
#### target_path_parameter

Refer to: http://symfony.com/doc/current/reference/configuration/security.html#redirecting-after-login

**Default**: `_target_path`

 ------------------
#### use_referrer

Refer to: http://symfony.com/doc/current/reference/configuration/security.html#redirecting-after-login

**Default**: `false`

 ------------------
#### failure_path

Refer to: http://symfony.com/doc/current/reference/configuration/security.html#full-default-configuration

**Default**: `null`

 ------------------
#### failure_forward

Refer to: http://symfony.com/doc/current/reference/configuration/security.html#full-default-configuration

**Default**: `false`

 ------------------
#### failure_path_parameter

Refer to: http://symfony.com/doc/current/reference/configuration/security.html#full-default-configuration

**Default**: `_failure_path`

## Doctrine

All of these options fall underneath the `doctrine` section of `ldap_tools`

 ------------------
#### integration_enabled

Whether or not Doctrine integration should be enabled. When enabled an event subscriber is used to watch for lifecycle 
events and trigger LDAP queries for entity properties using LdapObject annotations.

**Default**: `true`

 ------------------
#### connections

Which Doctrine connection name to integrate with. By default it will integrate with all connections. You can limit it to
only a specific connection or multiple connections

```php
ldap_tools:
    doctrine:
        # only integrate with these two connection names...
        connections:
            - 'foo'
            - 'bar'
```

**Default**: `null`

## LdapTools

For LdapTools general settings, use the section `general`. For general setting options, see the [LdapTools docs](https://github.com/ldaptools/ldaptools/blob/master/docs/en/reference/Main-Configuration.md#general-section).

All domains are defined under the `domains` section. For domain setting options, see the [LdapTools docs](https://github.com/ldaptools/ldaptools/blob/master/docs/en/reference/Main-Configuration.md#domain-section).

```php
ldap_tools:
    domains:
        example:
            # domain options here...
        another:
            # options for another domain...
```
