# LdapToolsBundle
-----------

The LdapToolsBundle provides easy integration of LDAP for Symfony via [LdapTools](https://github.com/ldaptools/ldaptools).

* An LDAP authentication provider, including AdvancedUserInterface support.
* An LDAP form type to easily use LDAP objects in forms.
* An LDAP type for Doctrine to easily store and retrieve LDAP results in a Doctrine entity.
* Logging capabilities for LDAP operations.
* Web Debug Toolbar integration for LDAP operations.
* Integration of LdapTools events for LDAP operations (authentication, creation, modification, etc) using service tags.

**Note**: The LdapTools library requires PHP 5.6+.

### Installation

The recommended way to install LdapTools is using [Composer](http://getcomposer.org/download/):

```bash
composer require ldaptools/ldaptools-bundle
```

Then enable the bundle in the kernel:

```php
// app/AppKernel.php
class AppKernel extends Kernel
{
    public function registerBundles()
    {
        $bundles = array(
            // ...
            new LdapTools\Bundle\LdapToolsBundle\LdapToolsBundle(),
        );

        // ...
    }
}
```

### Getting Started

After installing the bundle, configure it with the LDAP domains you want to use:

```yaml
# app/config/config.yml
ldap_tools:
    domains:
        # The below "example" key can be anything you want. It just has to be a unique name for the YML config.
        example:
            # The LDAP FQDN is required
            domain_name: example.local
            # The username to use for the LDAP connection
            username: foo
            # The password to use for the username
            password: secret
            # The base DN for LDAP searches (queried from the RootDSE if not provided)
            base_dn: "dc=example,dc=local"
            # The LDAP servers to use for the connection (Queried from DNS if not provided)
            servers: ["dc1", "dc2", "dc3"]
        # Define another domain if you want
        foo:
            domain_name: foo.bar
            username: foo
            password: bar
            servers: ['dc1.foo.bar', 'dc2.foo.bar']
            base_dn: 'dc=foo,dc=bar'
```

Then in your controller you can use the `ldap_tools.ldap_manager` service to query/modify/create LDAP objects...

```php

class DefaultController extends Controller
{
    public function indexAction()
    {
        $ldap = $this->get('ldap_tools.ldap_manager');
        
        $users = $ldap->buildLdapQuery()->fromUsers()->getLdapQuery()->getResult();
        
        $users->count();
        foreach ($users as $user) {
            $user->getFirstName();
            $user->getFirstName();
            $user->getUsername();
        }
        
        # ...
    }
}
```

### Documentation

* [LDAP Authentication Provider](/Resources/doc/LDAP-Authentication-Provider.md)
