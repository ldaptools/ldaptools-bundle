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
use LdapTools\Query\LdapQueryBuilder;

/**
 * Removes duplication between the Choice List and the Choice Loader.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
trait LdapObjectChoiceTrait
{
    /**
     * @var \Closure|null
     */
    protected $queryCallback;

    /**
     * @var LdapQueryBuilder|null
     */
    protected $ldapQueryBuilder;

    /**
     * @var LdapManager
     */
    protected $ldap;

    /**
     * @var string
     */
    protected $id;

    /**
     * @var string
     */
    protected $type;

    /**
     * @var string
     */
    protected $labelAttribute;

    /**
     * @param LdapQueryBuilder|\Closure|null $query
     */
    protected function setClosureOrQuery($query)
    {
        if ($query instanceof \Closure) {
            $this->queryCallback = $query;
        } elseif ($query instanceof LdapQueryBuilder) {
            $this->ldapQueryBuilder = $query;
        }
    }

    /**
     * Get the values of a set of choices.
     *
     * @param LdapObject[] $choices
     * @return array
     */
    protected function getLdapValuesForChoices(LdapObject ...$choices)
    {
        $values = [];

        foreach ($choices as $i => $ldapObject) {
            $values[$i] = (string) $ldapObject->get($this->id);
        }

        return $values;
    }

    /**
     * Get the LDAP objects from LDAP. Optionally only get those specified by the passed values.
     *
     * @param array $values The values used to narrow the LDAP query.
     * @return \LdapTools\Object\LdapObjectCollection
     */
    protected function getLdapObjectsByQuery($values = [])
    {
        if (!$this->ldapQueryBuilder) {
            $query = $this->ldap->buildLdapQuery()
                ->select([$this->id, $this->labelAttribute])
                ->from($this->type);
        } else {
            $query = clone $this->ldapQueryBuilder;
        }

        if (!empty($values)) {
            foreach ($values as $value) {
                $query->orWhere([$this->id => $value]);
            }
        }
        if ($this->queryCallback) {
            $closure = $this->queryCallback;
            $closure($query);
        }

        return $query->getLdapQuery()->getResult();
    }
}
