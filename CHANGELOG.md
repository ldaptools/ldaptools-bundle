CHANGELOG
=========

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
