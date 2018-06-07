CHANGELOG
=========

0.9.2 (2018-06-07)
------------------
  * Rename the option use_referrer to use_referer to match Symfony.

0.9.1 (2018-03-23)
------------------
  * Do not query LDAP for mapped roles if none are defined.

0.9.0 (2017-12-10)
------------------
  * Correct deprecations in Symfony 3.4, 4.0.
  * Add HTTP basic auth support.
  * Allow the LDAP Guard to be more easily extended.
  * Bump composer requirements for Symfony 4.0.

0.8.1 (2017-08-13)
------------------
  * Correct a deprecation in the Active Directory Response Code checking.

0.8.0 (2017-08-13)
------------------
  * Bumped the minimum Symfony version requirement to 2.7.
  * Improved the default LDAP authenticator bind logic for OpenLDAP/AD.
  * The login username can now be configured to query LDAP for a DN to bind with for a given LDAP attribute.
  * LDAP Group-to-Role mapping is now usable as a service (ldap_tools.security.user.ldap_role_mapper).
  * The username/password is no longer required for the domain configurations.
  * By default domain configurations now lazy bind, and only connect/bind when absolutely needed.
  * Refactored configuration of the LDAP User Provider.
  * Bumped the minimum LdapTools version requirement.

0.7.0 (2017-04-14)
------------------  
  * Add Guard redirection settings to the security config section of the bundle.
  * Add Guard settings for: post_only, remember_me, username/password/domain parameters
  * Add Guard events to set a response object on: start, auth success, auth failure
  * Add a ldaptools:generate:config command to assist in generating your LDAP configuration.
  * Only search groups recursively when the LDAP type is Active Directory.
  * Do not use cache in debug/dev mode.

0.6.0 (2017-01-29)
------------------
  * Add better Doctrine integration configuration (specify Doctrine entity manager names, or disable them).
  * The LdapUser must implement the LdapUserInterface. Removes the dependency on the LdapObject class.
  * Add a command (ldaptools:generate:sslcert) to assist in retrieving the LDAP SSL certificate.

0.5.0 (2016-10-23)
------------------
  * By default user attributes/roles are no longer refreshed on each request. It is now configurable.
  * Add a before and after event when loading a user from the user provider.
  * Correct several specs, add the bump the PhpSpec version.
  * Add more docs and examples.

0.4.0 (2016-09-05)
------------------
  * Add a LDIF parser service. Allow tagging LDIF URL loaders to it.
  * Add token information to the LDAP login success event.
  * Correct several specs, add the build status to the readme.
  * Add the bundle to Scrutinizer and add the score to the readme.

0.3.0 (2016-08-22)
------------------
  * Allow group role mappings to be set by SID, GUID, DN or name.
  * Add the connect_timeout domain config option.
  * Add a LDAP login success event (ldap_tools_bundle.login.success).

0.2.0 (2016-06-26)
------------------
  * Add a LDAP Guard authenticator for newer Symfony versions (replaces the ldap_tools_form)
  * Add a schema_name domain config option (@rouet)
  * Add an idle_reconnect domain config option.
  * Fix several specs.
  * Bump the required version of LdapTools and CS-Fixer in composer. 

0.1.0 (2015-12-25)
------------------
  * Initial release.
