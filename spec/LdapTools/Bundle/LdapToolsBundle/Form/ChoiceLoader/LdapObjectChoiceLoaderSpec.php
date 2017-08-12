<?php
/**
 * This file is part of the LdapToolsBundle package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace spec\LdapTools\Bundle\LdapToolsBundle\Form\ChoiceLoader;

use LdapTools\LdapManager;
use LdapTools\Object\LdapObject;
use LdapTools\Object\LdapObjectCollection;
use LdapTools\Object\LdapObjectType;
use LdapTools\Query\LdapQuery;
use LdapTools\Query\LdapQueryBuilder;
use PhpSpec\ObjectBehavior;

/**
 * @require Symfony\Component\Form\ChoiceList\Loader\ChoiceLoaderInterface
 */
class LdapObjectChoiceLoaderSpec extends ObjectBehavior
{
    public function let(LdapManager $ldap, LdapQueryBuilder $qb, LdapQuery $query)
    {
        $ldap->buildLdapQuery()->willReturn($qb);
        $qb->getLdapQuery()->willReturn($query);

        $this->beConstructedWith($ldap, LdapObjectType::USER);
    }

    function it_is_initializable()
    {
        $this->shouldHaveType('LdapTools\Bundle\LdapToolsBundle\Form\ChoiceLoader\LdapObjectChoiceLoader');
    }

    function it_should_load_a_choice_list($qb, $query)
    {
        // These are the default attributes it should select (name/value for the choice)
        $qb->select(['guid', 'name'])->shouldBeCalled()->willReturn($qb);
        $qb->from("user")->shouldBeCalled()->willReturn($qb);

        $collection = new LdapObjectCollection(
            new LdapObject(['name' => 'foo', 'guid' => '123'], 'user'),
            new LdapObject(['name' => 'bar', 'guid' => '456'], 'user')
        );
        $query->getResult()->shouldBeCalled()->willReturn($collection);

        $this->loadChoiceList()->shouldBeAnInstanceOf('\Symfony\Component\Form\ChoiceList\ArrayChoiceList');
    }

    function it_should_not_query_ldap_if_it_already_loaded_the_choicelist($qb, $query)
    {
        // These are the default attributes it should select (name/value for the choice)
        $qb->select(['guid', 'name'])->shouldBeCalled()->willReturn($qb);
        $qb->from("user")->shouldBeCalled()->willReturn($qb);

        $collection = new LdapObjectCollection(
            new LdapObject(['name' => 'foo', 'guid' => '123'], 'user'),
            new LdapObject(['name' => 'bar', 'guid' => '456'], 'user')
        );
        $query->getResult()->shouldBeCalledTimes(1)->willReturn($collection);

        $this->loadChoiceList()->shouldBeAnInstanceOf('\Symfony\Component\Form\ChoiceList\ArrayChoiceList');
        // The second call should just load the already returned choice list..
        $this->loadChoiceList()->shouldBeAnInstanceOf('\Symfony\Component\Form\ChoiceList\ArrayChoiceList');
    }

    function it_should_support_setting_the_ldap_type_and_choice_label_and_values($ldap, $qb, $query)
    {
        $this->beConstructedWith($ldap, LdapObjectType::GROUP, 'upn', 'sid');

        // These are the default attributes it should select (name/value for the choice)
        $qb->select(['sid', 'upn'])->shouldBeCalled()->willReturn($qb);
        $qb->from("group")->shouldBeCalled()->willReturn($qb);

        $collection = new LdapObjectCollection(
            new LdapObject(['upn' => 'foo', 'sid' => '123'], 'group'),
            new LdapObject(['upn' => 'bar', 'sid' => '456'], 'group')
        );
        $query->getResult()->shouldBeCalled()->willReturn($collection);

        $this->loadChoiceList()->shouldBeAnInstanceOf('\Symfony\Component\Form\ChoiceList\ArrayChoiceList');
    }

    function it_should_support_setting_a_specific_ldap_query_builder_to_load_the_choicelist($ldap, $qb, $query)
    {
        $this->beConstructedWith($ldap, LdapObjectType::GROUP, 'upn', 'sid', $qb);
        $qb->getLdapQuery()->shouldBeCalled()->willReturn($query);

        $collection = new LdapObjectCollection(
            new LdapObject(['upn' => 'foo', 'sid' => '123'], 'group'),
            new LdapObject(['upn' => 'bar', 'sid' => '456'], 'group')
        );
        $query->getResult()->shouldBeCalled()->willReturn($collection);

        $this->loadChoiceList()->shouldBeAnInstanceOf('\Symfony\Component\Form\ChoiceList\ArrayChoiceList');
    }

    function it_should_support_calling_a_closure_against_the_query_builder_when_loading_the_choicelist($qb, $query, $ldap)
    {
        $foo = function($qb) {
            $qb->where(['foo' => 'bar']);
        };
        $this->beConstructedWith($ldap, LdapObjectType::GROUP, 'upn', 'sid', $foo);

        // These are the default attributes it should select (name/value for the choice)
        $qb->select(['sid', 'upn'])->shouldBeCalled()->willReturn($qb);
        $qb->from("group")->shouldBeCalled()->willReturn($qb);

        $collection = new LdapObjectCollection(
            new LdapObject(['upn' => 'foo', 'sid' => '123'], 'group'),
            new LdapObject(['upn' => 'bar', 'sid' => '456'], 'group')
        );
        $query->getResult()->shouldBeCalled()->willReturn($collection);

        // As the result of the closure...
        $qb->where(['foo' => 'bar'])->shouldBeCalled();

        $this->loadChoiceList()->shouldBeAnInstanceOf('\Symfony\Component\Form\ChoiceList\ArrayChoiceList');
    }

    function it_should_load_values_for_choices($qb, $query)
    {
        $collection = new LdapObjectCollection(
            new LdapObject(['name' => 'foo', 'guid' => '123'], 'user'),
            new LdapObject(['name' => 'bar', 'guid' => '456'], 'user')
        );

        $this->loadValuesForChoices($collection->toArray())->shouldBeEqualTo(['123', '456']);

        $qb->select(['guid', 'name'])->shouldBeCalled()->willReturn($qb);
        $qb->from("user")->shouldBeCalled()->willReturn($qb);

        $collection = new LdapObjectCollection(
            new LdapObject(['name' => 'foo', 'guid' => '123'], 'user'),
            new LdapObject(['name' => 'bar', 'guid' => '456'], 'user')
        );
        $query->getResult()->shouldBeCalled()->willReturn($collection);

        $this->loadChoiceList();
        $this->loadValuesForChoices($collection->toArray())->shouldBeEqualTo(['123', '456']);
    }

    function it_should_load_choices_for_values($qb, $query)
    {
        $qb->select(['guid', 'name'])->shouldBeCalled()->willReturn($qb);
        $qb->from("user")->shouldBeCalled()->willReturn($qb);

        $user1 = new LdapObject(['name' => 'foo', 'guid' => '123'], 'user');
        $user2 = new LdapObject(['name' => 'bar', 'guid' => '456'], 'user');
        $collection = new LdapObjectCollection(
            $user1,
            $user2
        );
        $query->getResult()->shouldBeCalledTimes(1)->willReturn($collection);

        $this->loadChoicesForValues(['123'])->shouldBeEqualTo([$user1]);
        $this->loadChoicesForValues(['456'])->shouldBeEqualTo([$user2]);
        $this->loadChoicesForValues([])->shouldBeEqualTo([]);
    }
}
