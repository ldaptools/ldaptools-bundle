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

class LegacyLdapChoiceLoaderSpec extends ObjectBehavior
{
    public function let(LdapManager $ldap, LdapQueryBuilder $qb, LdapQuery $query)
    {
        $ldap->buildLdapQuery()->willReturn($qb);
        $qb->getLdapQuery()->willReturn($query);
        $this->beConstructedWith($ldap, LdapObjectType::USER);
    }

    function it_is_initializable()
    {
        $this->shouldHaveType('LdapTools\Bundle\LdapToolsBundle\Form\ChoiceLoader\LegacyLdapChoiceLoader');
    }

    function it_should_load_a_set_of_choices_as_ldap_objects($qb, $query)
    {
        // These are the default attributes it should select (name/value for the choice)
        $qb->select(['guid', 'name'])->shouldBeCalled()->willReturn($qb);
        $qb->from("user")->shouldBeCalled()->willReturn($qb);

        $collection = new LdapObjectCollection(
            new LdapObject(['name' => 'foo', 'guid' => '123'], ['user'], 'user', 'user'),
            new LdapObject(['name' => 'bar', 'guid' => '456'], ['user'], 'user', 'user')
        );
        $query->getResult()->shouldBeCalled()->willReturn($collection);

        $this->load()->shouldBeEqualTo($collection->toArray());
    }

    function it_should_support_calling_a_closure_against_the_query_builder_when_loading_the_choices($qb, $query, $ldap)
    {
        $foo = function($qb) {
            $qb->where(['foo' => 'bar']);
        };
        $this->beConstructedWith($ldap, LdapObjectType::GROUP, 'upn', 'sid', $foo);

        // These are the default attributes it should select (name/value for the choice)
        $qb->select(['sid', 'upn'])->shouldBeCalled()->willReturn($qb);
        $qb->from("group")->shouldBeCalled()->willReturn($qb);

        $collection = new LdapObjectCollection(
            new LdapObject(['upn' => 'foo', 'sid' => '123'], ['group'], 'group', 'group'),
            new LdapObject(['upn' => 'bar', 'sid' => '456'], ['group'], 'group', 'group')
        );
        $query->getResult()->shouldBeCalled()->willReturn($collection);

        // As the result of the closure...
        $qb->where(['foo' => 'bar'])->shouldBeCalled();

        $this->load()->shouldBeEqualTo($collection->toArray());
    }

    function it_should_support_setting_a_specific_ldap_query_builder_to_load_the_choicelist($qb, $ldap, $query)
    {
        $this->beConstructedWith($ldap, LdapObjectType::GROUP, 'upn', 'sid', $qb);
        $qb->getLdapQuery()->shouldBeCalled()->willReturn($query);

        $collection = new LdapObjectCollection(
            new LdapObject(['upn' => 'foo', 'sid' => '123'], ['group'], 'group', 'group'),
            new LdapObject(['upn' => 'bar', 'sid' => '456'], ['group'], 'group', 'group')
        );
        $query->getResult()->shouldBeCalled()->willReturn($collection);

        $this->load()->shouldBeEqualTo($collection->toArray());
    }
}
