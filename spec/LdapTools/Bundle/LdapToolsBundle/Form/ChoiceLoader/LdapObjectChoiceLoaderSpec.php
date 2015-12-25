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

/**
 * @require Symfony\Component\Form\ChoiceList\Loader\ChoiceLoaderInterface
 */
class LdapObjectChoiceLoaderSpec extends ObjectBehavior
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
        $this->shouldHaveType('LdapTools\Bundle\LdapToolsBundle\Form\ChoiceLoader\LdapObjectChoiceLoader');
    }

    function it_should_load_a_choice_list()
    {
        // These are the default attributes it should select (name/value for the choice)
        $this->qb->select(['guid', 'name'])->shouldBeCalled()->willReturn($this->qb);
        $this->qb->from("user")->shouldBeCalled()->willReturn($this->qb);

        $collection = new LdapObjectCollection(
            new LdapObject(['name' => 'foo', 'guid' => '123'], ['user'], 'user', 'user'),
            new LdapObject(['name' => 'bar', 'guid' => '456'], ['user'], 'user', 'user')
        );
        $this->query->getResult()->shouldBeCalled()->willReturn($collection);

        $this->loadChoiceList()->shouldBeAnInstanceOf('\Symfony\Component\Form\ChoiceList\ArrayChoiceList');
    }

    function it_should_not_query_ldap_if_it_already_loaded_the_choicelist()
    {
        // These are the default attributes it should select (name/value for the choice)
        $this->qb->select(['guid', 'name'])->shouldBeCalled()->willReturn($this->qb);
        $this->qb->from("user")->shouldBeCalled()->willReturn($this->qb);

        $collection = new LdapObjectCollection(
            new LdapObject(['name' => 'foo', 'guid' => '123'], ['user'], 'user', 'user'),
            new LdapObject(['name' => 'bar', 'guid' => '456'], ['user'], 'user', 'user')
        );
        $this->query->getResult()->shouldBeCalledTimes(1)->willReturn($collection);

        $this->loadChoiceList()->shouldBeAnInstanceOf('\Symfony\Component\Form\ChoiceList\ArrayChoiceList');
        // The second call should just load the already returned choice list..
        $this->loadChoiceList()->shouldBeAnInstanceOf('\Symfony\Component\Form\ChoiceList\ArrayChoiceList');
    }

    function it_should_support_setting_the_ldap_type_and_choice_label_and_values()
    {
        $this->beConstructedWith($this->ldap, LdapObjectType::GROUP, 'upn', 'sid');

        // These are the default attributes it should select (name/value for the choice)
        $this->qb->select(['sid', 'upn'])->shouldBeCalled()->willReturn($this->qb);
        $this->qb->from("group")->shouldBeCalled()->willReturn($this->qb);

        $collection = new LdapObjectCollection(
            new LdapObject(['upn' => 'foo', 'sid' => '123'], ['group'], 'group', 'group'),
            new LdapObject(['upn' => 'bar', 'sid' => '456'], ['group'], 'group', 'group')
        );
        $this->query->getResult()->shouldBeCalled()->willReturn($collection);

        $this->loadChoiceList()->shouldBeAnInstanceOf('\Symfony\Component\Form\ChoiceList\ArrayChoiceList');
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

        $this->loadChoiceList()->shouldBeAnInstanceOf('\Symfony\Component\Form\ChoiceList\ArrayChoiceList');
    }

    function it_should_support_calling_a_closure_against_the_query_builder_when_loading_the_choicelist()
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

        $this->loadChoiceList()->shouldBeAnInstanceOf('\Symfony\Component\Form\ChoiceList\ArrayChoiceList');
    }

    function it_should_load_values_for_choices()
    {
        $collection = new LdapObjectCollection(
            new LdapObject(['name' => 'foo', 'guid' => '123'], ['user'], 'user', 'user'),
            new LdapObject(['name' => 'bar', 'guid' => '456'], ['user'], 'user', 'user')
        );

        $this->loadValuesForChoices($collection->toArray())->shouldBeEqualTo(['123', '456']);

        $this->qb->select(['guid', 'name'])->shouldBeCalled()->willReturn($this->qb);
        $this->qb->from("user")->shouldBeCalled()->willReturn($this->qb);

        $collection = new LdapObjectCollection(
            new LdapObject(['name' => 'foo', 'guid' => '123'], ['user'], 'user', 'user'),
            new LdapObject(['name' => 'bar', 'guid' => '456'], ['user'], 'user', 'user')
        );
        $this->query->getResult()->shouldBeCalled()->willReturn($collection);

        $this->loadChoiceList();
        $this->loadValuesForChoices($collection->toArray())->shouldBeEqualTo(['123', '456']);
    }

    function it_should_load_choices_for_values()
    {
        $this->qb->select(['guid', 'name'])->shouldBeCalled()->willReturn($this->qb);
        $this->qb->from("user")->shouldBeCalled()->willReturn($this->qb);

        $user1 = new LdapObject(['name' => 'foo', 'guid' => '123'], ['user'], 'user', 'user');
        $user2 = new LdapObject(['name' => 'bar', 'guid' => '456'], ['user'], 'user', 'user');
        $collection = new LdapObjectCollection(
            $user1,
            $user2
        );
        $this->query->getResult()->shouldBeCalledTimes(1)->willReturn($collection);

        $this->loadChoicesForValues(['123'])->shouldBeEqualTo([$user1]);
        $this->loadChoicesForValues(['456'])->shouldBeEqualTo([$user2]);
        $this->loadChoicesForValues([])->shouldBeEqualTo([]);
    }
}
