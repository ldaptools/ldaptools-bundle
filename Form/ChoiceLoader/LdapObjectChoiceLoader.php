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
use Symfony\Component\Form\ChoiceList\ChoiceListInterface;
use Symfony\Component\Form\ChoiceList\Factory\ChoiceListFactoryInterface;
use Symfony\Component\Form\ChoiceList\Factory\DefaultChoiceListFactory;
use Symfony\Component\Form\ChoiceList\Factory\PropertyAccessDecorator;
use Symfony\Component\Form\ChoiceList\Loader\ChoiceLoaderInterface;

/**
 * Provides a choice list loader for LDAP objects.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class LdapObjectChoiceLoader implements ChoiceLoaderInterface
{
    use LdapObjectChoiceTrait;

    /**
     * @var ChoiceListFactoryInterface
     */
    private $factory;

    /**
     * @var ChoiceListInterface|null
     */
    protected $choiceList;

    /**
     * @param LdapManager $ldap
     * @param string $type The LDAP object type.
     * @param string $labelAttribute The LDAP attribute to use for the label.
     * @param string $id The attribute to use for the ID.
     * @param LdapQueryBuilder|\Closure|null
     */
    public function __construct(LdapManager $ldap, $type, $labelAttribute = 'name', $id = 'guid', $query = null)
    {
        $this->factory = new PropertyAccessDecorator(new DefaultChoiceListFactory());
        $this->ldap = $ldap;
        $this->type = $type;
        $this->id = $id;
        $this->labelAttribute = $labelAttribute;
        $this->setClosureOrQuery($query);
    }

    /**
     * {@inheritdoc}
     */
    public function loadChoiceList($value = null)
    {
        if ($this->choiceList) {
            return $this->choiceList;
        }
        $ldapObjects = $this->getLdapObjectsByQuery();

        $choices = [];
        /** @var LdapObject $object */
        foreach ($ldapObjects as $object) {
            $choices[$object->get($this->labelAttribute)] = $object;
        }
        $this->choiceList = $this->factory->createListFromChoices($choices, $this->id);

        return $this->choiceList;
    }

    /**
     * {@inheritdoc}
     */
    public function loadValuesForChoices(array $choices, $value = null)
    {
        if (empty(array_filter($choices))) {
            return [];
        }
        if (!$this->choiceList) {
            return $this->getLdapValuesForChoices(...$choices);
        }

        return $this->loadChoiceList($value)->getValuesForChoices($choices);
    }

    /**
     * {@inheritdoc}
     */
    public function loadChoicesForValues(array $values, $value = null)
    {
        if (empty(array_filter($values))) {
            return [];
        }
        if (!$this->choiceList) {
            $this->loadChoiceList($value);
        }

        return $this->choiceList->getChoicesForValues($values);
    }
}
