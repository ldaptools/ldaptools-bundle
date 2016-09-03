LDIF Parser URL Loaders
================

The LdapTools library includes a [LDIF Parser](https://github.com/ldaptools/ldaptools/blob/master/docs/en/tutorials/LDIF-Files.md) capable of loading LDIF values from a URL (such as `http://` or `file://`).
By default it only includes support for a limited number of URL types. If you have your own URL type you want to use in
a LDIF file to load data then you need to create a [LDIF URL Loader](https://github.com/ldaptools/ldaptools/blob/master/docs/en/tutorials/LDIF-Files.md#ldif-url-loaders) which is a class that implements `LdapTools\Ldif\UrlLoader\UrlLoaderInterface`.
Then you need to add an instance of that URL Loader to the LDIF Parser class via `setUrlLoader($type, $loader)`.

The above process is made easy in this bundle by first creating the LDIF URL Loader, registering it as a service, then simply
tagging the service with the `ldap_tools.ldif_url_loader` tag and a `type` property on the tag that defines the type of 
URL it is (ie. `https`, `file`, etc).

## Create the LDIF URL Loader

```php
namespace AppBundle\LdifUrlLoader;

use LdapTools\Ldif\LdifUrlLoader\UrlLoaderInterface;

class LdifHttpsLoader implements UrlLoaderInterface
{
    /**
     * {@inheritdoc}
     */
    public function load($url)
    {
        // Custom logic for your URL loading process here...
        
        // Return the resulting data...
        return $data;
    }
}
```

## Define the LDIF URL Loader as a Service

```yaml
<?xml version="1.0" ?>
    <!-- ... -->
    <services>
        <!-- ... -->
        
        <service id="app.ldif_url_loader" class="AppBundle\LdifUrlLoader\LdifHttpsLoader" >
            <tag name="ldap_tools.ldif_url_loader" type="https"/>
        </service>
        
        <!-- ... -->
    </services>
</container>
```

Now in your LDIF files your URL loader will be used when parsing files that consume data from the URL.

Assume a LDIF file with an entry like:

```
dn: cn=Barbara Jensen, ou=Product Development, dc=airius, dc=com
objectclass: top
objectclass: person
objectclass: organizationalPerson
cn: Barbara Jensen
sn: Jensen
uid: bjensen
telephonenumber: +1 408 555 1212
description:< https://example.local/users/bjensen.html
```

The `description` at the bottom will be loaded from the URL Loader, such as in a controller:

```php

class DefaultController extends Controller
{
    public function indexAction()
    {
        try {
            # Use the LDIF parser from the service which will have the URL loader set...
            $ldif = $this->get('ldap_tools.ldif_parser')->parse(file_get_contents('/path/to/ldif.txt'));
        } catch (LdifParserException $e) {
            echo "Error Parsing LDIF: ".$e->getMessage();
        }
        
        // Iterate through the operations parsed from the LDIF file...
        foreach ($ldif->toOperations() as $operation) {
             // Load them into LDAP if you want...
             $this->get('ldap_tools.ldap_manager')->getConnection()->execute($operation);
        }
        
        # ...
    }
}
```
