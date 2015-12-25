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
use Prophecy\Argument;

class LegacyLdapChoiceLoaderSpec extends ObjectBehavior
{
    /**
     * @var LdapManager
     */
    protected $ldap;

    /**
     * @var LdapQueryBuilder
     */
    protected $qb;

    /**
     * @var LdapQuery
     */
    protected $query;

    /**
     * @var LdapObjectCollection
     */
    protected $result;

    /**
     * @param \LdapTools\LdapManager $ldap
     * @param \LdapTools\Query\LdapQueryBuilder $qb
     * @param \LdapTools\Query\LdapQuery $query
     * @param \LdapTools\Object\LdapObjectCollection $result
     */
    public function let($ldap, $qb, $query, $result)
    {
        $this->ldap = $ldap;
        $this->qb = $qb;
        $this->query = $query;
        $this->ldap->buildLdapQuery()->willReturn($this->qb);
        $this->qb->getLdapQuery()->willReturn($this->query);
        $this->result = $result;
        $this->beConstructedWith($ldap, LdapObjectType::USER);
    }

    function it_is_initializable()
    {
        $this->shouldHaveType('LdapTools\Bundle\LdapToolsBundle\Form\ChoiceLoader\LegacyLdapChoiceLoader');
    }

    function it_should_load_a_set_of_choices_as_ldap_objects()
    {
        // These are the default attributes it should select (name/value for the choice)
        $this->qb->select(['guid', 'name'])->shouldBeCalled()->willReturn($this->qb);
        $this->qb->from("user")->shouldBeCalled()->willReturn($this->qb);

        $collection = new LdapObjectCollection(
            new LdapObject(['name' => 'foo', 'guid' => '123'], ['user'], 'user', 'user'),
            new LdapObject(['name' => 'bar', 'guid' => '456'], ['user'], 'user', 'user')
        );
        $this->query->getResult()->shouldBeCalled()->willReturn($collection);

        $this->load()->shouldBeEqualTo($collection->toArray());
    }

    function it_should_support_calling_a_closure_against_the_query_builder_when_loading_the_choices()
    {
        $foo = function($qb) {
            $qb->where(['foo' => 'bar']);
        };
        $this->beConstructedWith($this->ldap, LdapObjectType::GROUP, 'upn', 'sid', $foo);

        // These are the default attributes it should select (name/value for the choice)
        $this->qb->select(['sid', 'upn'])->shouldBeCalled()->willReturn($this->qb);
        $this->qb->from("group")->shouldBeCalled()->willReturn($this->qb);

        $collection = new LdapObjectCollection(
            new LdapObject(['upn' => 'foo', 'sid' => '123'], ['group'], 'group', 'group'),
            new LdapObject(['upn' => 'bar', 'sid' => '456'], ['group'], 'group', 'group')
        );
        $this->query->getResult()->shouldBeCalled()->willReturn($collection);

        // As the result of the closure...
        $this->qb->where(['foo' => 'bar'])->shouldBeCalled();

        $this->load()->shouldBeEqualTo($collection->toArray());
    }

    /**
     * @param \LdapTools\Query\LdapQueryBuilder $qb
     */
    function it_should_support_setting_a_specific_ldap_query_builder_to_load_the_choicelist($qb)
    {
        $this->beConstructedWith($this->ldap, LdapObjectType::GROUP, 'upn', 'sid', $qb);
        $qb->getLdapQuery()->shouldBeCalled()->willReturn($this->query);

        $collection = new LdapObjectCollection(
            new LdapObject(['upn' => 'foo', 'sid' => '123'], ['group'], 'group', 'group'),
            new LdapObject(['upn' => 'bar', 'sid' => '456'], ['group'], 'group', 'group')
        );
        $this->query->getResult()->shouldBeCalled()->willReturn($collection);

        $this->load()->shouldBeEqualTo($collection->toArray());
    }
}
