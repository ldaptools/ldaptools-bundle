<?php
/**
 * This file is part of the LdapToolsBundle package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace LdapTools\Bundle\LdapToolsBundle\Form\ChoiceLoader;

use LdapTools\LdapManager;
use LdapTools\Object\LdapObject;

/**
 * Gets an array of LDAP objects to be passed to the ObjectChoiceList for pre-Symfony 2.7 compatibility.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class LegacyLdapChoiceLoader
{
    use LdapObjectChoiceTrait;

    /**
     * @param LdapManager $ldap
     * @param string $type The LDAP object type.
     * @param string $labelAttribute The LDAP attribute to use for the label.
     * @param string $id The attribute to use for the ID.
     * @param LdapQueryBuilder|\Closure|null
     */
    public function __construct(LdapManager $ldap, $type, $labelAttribute = 'name', $id = 'guid', $query = null)
    {
        $this->ldap = $ldap;
        $this->type = $type;
        $this->id = $id;
        $this->labelAttribute = $labelAttribute;
        $this->setClosureOrQuery($query);
    }

    /**
     * @return LdapObject[]
     */
    public function load()
    {
        return $this->getLdapObjectsByQuery()->toArray();
    }
}
