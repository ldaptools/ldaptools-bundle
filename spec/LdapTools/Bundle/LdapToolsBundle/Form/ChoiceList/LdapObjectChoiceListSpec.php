<?php
/**
 * This file is part of the LdapToolsBundle package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace spec\LdapTools\Bundle\LdapToolsBundle\Form\ChoiceList;

use LdapTools\Object\LdapObject;
use PhpSpec\ObjectBehavior;

/**
 * @require Symfony\Component\Form\Extension\Core\ChoiceList\ObjectChoiceList
 */
class LdapObjectChoiceListSpec extends ObjectBehavior
{
    /**
     * @var LdapObject[]
     */
    protected $ldapObjects = [];

    function let()
    {
        $this->ldapObjects = [
            new LdapObject(['guid' => 'foo', 'name' => 'bar']),
            new LdapObject(['guid' => 'bar', 'name' => 'foo']),
        ];

        $this->beConstructedWith($this->ldapObjects, 'name', [], null, 'guid', null);
    }

    function it_is_initializable()
    {
        $this->shouldHaveType('LdapTools\Bundle\LdapToolsBundle\Form\ChoiceList\LdapObjectChoiceList');
    }

    function it_should_extend_the_object_choice_list()
    {
        $this->shouldReturnAnInstanceOf('Symfony\Component\Form\Extension\Core\ChoiceList\ObjectChoiceList');
    }

    function it_should_get_the_choices_from_values()
    {
        $this->getChoicesForValues(['foo'])->shouldBeEqualTo([$this->ldapObjects[0]]);
        $this->getChoicesForValues(['foo','bar'])->shouldBeEqualTo($this->ldapObjects);
    }

    function it_should_get_the_values_from_choices()
    {
        $this->getValuesForChoices([$this->ldapObjects[1]])->shouldBeEqualTo(['bar']);
        $this->getValuesForChoices($this->ldapObjects)->shouldBeEqualTo(['foo', 'bar']);
    }

    function it_should_get_the_indices_for_choices()
    {
        $this->getIndicesForChoices([$this->ldapObjects[1]])->shouldBeEqualTo([0 => 1]);
        $this->getIndicesForChoices(array_reverse($this->ldapObjects))->shouldBeEqualTo([0 => 1, 1 => 0]);
        $this->getIndicesForChoices($this->ldapObjects)->shouldBeEqualTo([0 => 0, 1 => 1]);
    }

    function it_should_get_the_indices_for_values()
    {
        $this->getIndicesForValues(['foo'])->shouldBeEqualTo([0 => 0]);
        $this->getIndicesForValues(['bar', 'foo'])->shouldBeEqualTo([0 => 1, 1 => 0]);
        $this->getIndicesForValues(['foo', 'bar'])->shouldBeEqualTo([0 => 0, 1 => 1]);
    }
}
