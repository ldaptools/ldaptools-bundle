LDAP Object Form Type
================

The LDAP object form type provides a simple method of displaying different types of LDAP objects in a choice selection
format for a form. This can be combined with the LDAP object Doctrine type to easily store/retrieve specific LDAP objects
when working with a form that relates to a Doctrine entity.

The form type can be used as follows:

```php
use LdapTools\Bundle\LdapToolsBundle\Form\Type\LdapObjectType;

# ...

$form = $this->createFormBuilder()
    // For Symfony 2.3 - 2.7, replace LdapObjectType::class with "ldap_object".
    ->add('ldap', LdapObjectType::class, [
        // The ldap_type can be any valid LdapTools type. Such as: user, computer, contact, etc.
        'ldap_type' => 'group',
        // The ldap_query_builder allows a closure to further limit/filter what LDAP objects show up.
        // Omit this and you will get all of the specified 'ldap_type'.
        'ldap_query_builder' => function (LdapQueryBuilder $query) {
          $query->andWhere($query->filter()->startsWith('name', 'App-'));
        }
    ])
    ->add('send', SubmitType::class)
    ->getForm();
```

## LDAP Object Form Types and Doctrine Entities

Often times you will probably be working with a form that relates to a Doctrine entity. You can relate the the LDAP 
object form type to a column with a special annotation that will easily load/save the LDAP object to the entity to
eliminate some extra work:

```php
# On the entity where your form is saved...

use LdapTools\Bundle\LdapToolsBundle\Annotation as LdapTools;

/**
 * User
 *
 * @ORM\Table()
 * @ORM\Entity
 */
class User
{
    #...
    
    /**
     * @var LdapObject
     *
     * @ORM\Column(name="ldapGroup", type="ldap_object")
     * @LdapTools\LdapObject(type="group")
     */
    private $ldapGroup;
    
    # ...
}
```

Then you just follow the initial instructions at the start of this document to setup the LdapObjectType on your form and
tie it to the `$ldapGroup` column in the example above.

The above is an example of saving a specific LDAP object to a column. If your form type allows for multiple values to be
selected, then you need to modify the annotation on your entity a bit so it knows that it is expecting a collection of
LDAP objects:

```php
# On the entity where your form is saved...

use LdapTools\Bundle\LdapToolsBundle\Annotation as LdapTools;

/**
 * User
 *
 * @ORM\Table()
 * @ORM\Entity
 */
class User
{
    #...
    
    /**
     * @var LdapObjectCollection
     *
     * @ORM\Column(name="ldapGroups", type="ldap_object_collection")
     * @LdapTools\LdapObject(type="group", collection=true)
     */
    private $ldapGroups;
    
    # ...
}
```
