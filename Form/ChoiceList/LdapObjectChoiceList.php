<?php
/**
 * This file is part of the LdapToolsBundle package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace LdapTools\Bundle\LdapToolsBundle\Form\ChoiceList;

use LdapTools\Object\LdapObject;
use Symfony\Component\Form\Extension\Core\ChoiceList\ObjectChoiceList;

/**
 * Overrides certain ChoiceList methods so the old extended ObjectChoiceList works properly
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class LdapObjectChoiceList extends ObjectChoiceList
{
    /**
     * @var LdapObject[]
     */
    protected $ldapObjects;

    /**
     * @var string
     */
    protected $id;

    /**
     * LdapObjectChoiceList constructor.
     * @param array|\Traversable $choices
     * @param null $labelPath
     * @param array $preferredChoices
     * @param null $groupPath
     * @param null $valuePath
     * @param PropertyAccessorInterface|null $propertyAccessor
     */
    public function __construct($choices, $labelPath = null, array $preferredChoices = array(), $groupPath = null, $valuePath = null, PropertyAccessorInterface $propertyAccessor = null)
    {
        $this->id = $valuePath;
        $this->ldapObjects = $choices;
        parent::__construct($choices, $labelPath, $preferredChoices, $groupPath, $valuePath);
    }

    /**
     * {@inheritdoc}
     */
    public function getChoicesForValues(array $values)
    {
        if (empty(array_filter($values))) {
            return [];
        }

        $choices = [];
        foreach ($values as $i => $value) {
            foreach ($this->ldapObjects as $ldapObject) {
                if ($ldapObject->has($this->id, $value)) {
                    $choices[$i] = $ldapObject;
                    break;
                }
            }
        }

        return $choices;
    }

    /**
     * {@inheritdoc}
     */
    public function getValuesForChoices(array $choices)
    {
        if (empty(array_filter($choices))) {
            return [];
        }

        $values = [];
        foreach ($choices as $i => $choice) {
            $values[$i] = $choice->get($this->id);
        }

        return $values;
    }

    /**
     * {@inheritdoc}
     */
    public function getIndicesForChoices(array $choices)
    {
        if (empty(array_filter($choices))) {
            return [];
        }

        $indices = [];
        foreach ($choices as $k => $choice) {
            foreach ($this->ldapObjects as $i => $ldapObject) {
                if ($ldapObject->has($this->id, $choice->get($this->id))) {
                    $indices[$k] = $i;
                    break;
                }
            }
        }

        return $indices;
    }

    /**
     * {@inheritdoc}
     */
    public function getIndicesForValues(array $values)
    {
        if (empty(array_filter($values))) {
            return [];
        }

        $indices = [];
        foreach ($values as $k => $value) {
            foreach ($this->ldapObjects as $i => $ldapObject) {
                if ($ldapObject->has($this->id, $value)) {
                    $indices[$k] = $i;
                    break;
                }
            }
        }

        return $indices;
    }
}
