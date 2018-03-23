<?php
/**
 * This file is part of the LdapToolsBundle package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace spec\LdapTools\Bundle\LdapToolsBundle\Security\User;

use LdapTools\Bundle\LdapToolsBundle\Security\User\LdapUser;
use LdapTools\Connection\LdapConnection;
use LdapTools\DomainConfiguration;
use LdapTools\LdapManager;
use LdapTools\Object\LdapObject;
use LdapTools\Object\LdapObjectCollection;
use LdapTools\Query\Builder\ADFilterBuilder;
use LdapTools\Query\LdapQuery;
use LdapTools\Query\LdapQueryBuilder;
use PhpSpec\ObjectBehavior;
use Prophecy\Argument;

class LdapRoleMapperSpec extends ObjectBehavior
{
    protected $user;

    protected $options = [
        'roles' => [
            'ROLE_AWESOME' => ['foo'],
            'ROLE_ADMIN' => ['291d8444-9d5b-4b0a-a6d7-853408f704d5'],
            'ROLE_DN' => ['cn=Stuff,dc=example,dc=local'],
            'ROLE_SID' => ['S-1-5-18'],
        ],
    ];

    function let(LdapManager $ldap, LdapQueryBuilder $qb, LdapQuery $query, LdapConnection $connection)
    {
        $this->user = new LdapUser();
        $this->user->refresh([
            'name' => 'Stuff',
            'username' => 'foo',
            'guid' => '291d8444-9d5b-4b0a-a6d7-853408f704d5',
            'dn' => 'cn=Stuff,dc=example,dc=local',
        ]);

        $groups = new LdapObjectCollection();
        $groups->add(new LdapObject(['name' => 'Foo', 'dn' => 'cn=Foo,dc=example,dc=local']));
        $groups->add(new LdapObject(['guid' => '291d8444-9d5b-4b0a-a6d7-853408f704d5', 'dn' => 'cn=Bar,dc=example,dc=local']));
        $groups->add(new LdapObject(['sid' => 'S-1-5-18', 'dn' => 'cn=LocalSys,dc=example,dc=local']));
        $groups->add(new LdapObject(['name' => 'Just a DN', 'dn' => 'cn=Stuff,dc=example,dc=local']));

        $filter = new ADFilterBuilder();
        $qb->filter()->willReturn($filter);
        $qb->where(Argument::type('LdapTools\Query\Operator\MatchingRule'))->willReturn($qb);
        $qb->from('group')->willReturn($qb);
        $qb->select(["guid", "sid", "name"])->willReturn($qb);

        $ldap->buildLdapQuery()->willReturn($qb);
        $qb->getLdapQuery()->willReturn($query);
        $query->getResult()->willReturn($groups);

        $config = new DomainConfiguration('foo.bar');

        $ldap->getDomainContext()->willReturn('foo.bar');
        $ldap->getConnection()->willReturn($connection);
        $connection->getConfig()->willReturn($config);

        $this->beConstructedWith($ldap, $this->options);
    }

    function it_is_initializable()
    {
        $this->shouldHaveType('LdapTools\Bundle\LdapToolsBundle\Security\User\LdapRoleMapper');
    }

    function it_should_set_the_roles_properly_for_the_returned_groups($query)
    {
        $this->setRoles($this->user)->getRoles()->shouldBeEqualTo(['ROLE_USER', 'ROLE_AWESOME', 'ROLE_ADMIN', 'ROLE_DN', 'ROLE_SID']);

        $query->getResult()->willReturn(new LdapObjectCollection(new LdapObject(['name' => 'foo'])));
        $this->setRoles($this->user)->getRoles()->shouldBeEqualTo(['ROLE_USER', 'ROLE_AWESOME']);

        $query->getResult()->willReturn(new LdapObjectCollection(new LdapObject(['name' => 'foo.bar'])));
        $this->setRoles($this->user)->getRoles()->shouldBeEqualTo(['ROLE_USER']);
    }

    function it_should_not_search_recursively_when_the_LDAP_type_is_openldap($qb, $connection)
    {
        $connection->getConfig()->willReturn((new DomainConfiguration('foo.bar'))->setLdapType('openldap'));

        $qb->where(Argument::type('LdapTools\Query\Operator\MatchingRule'))->shouldNotBeCalled();
        $qb->where(Argument::withKey('members'))->shouldBeCalled();

        $this->setRoles($this->user);
    }

    function it_should_search_recursively_when_the_LDAP_type_is_active_directory($qb)
    {
        $qb->where(Argument::type('LdapTools\Query\Operator\MatchingRule'))->shouldBeCalled();

        $this->setRoles($this->user);
    }

    function it_should_set_the_ldap_type_for_the_role_query($ldap, $qb)
    {
        $this->beConstructedWith($ldap, array_merge($this->options, ['role_ldap_type' => 'foo']));

        $qb->from('foo')->shouldBeCalled()->willReturn($qb);

        $this->setRoles($this->user);
    }

    function it_should_set_the_attribute_map_for_the_role_query($ldap, $qb)
    {
        $this->beConstructedWith($ldap, array_merge($this->options, ['role_attributes' => [
            'members' => 'members',
            'name' => 'cn',
            'guid' => 'foo',
            'sid' => 'bar'
        ]]));

        $qb->select(['cn', 'foo', 'bar'])->shouldBeCalled()->willReturn($qb);

        $this->setRoles($this->user);
    }

    function it_should_not_set_a_default_role_if_it_is_set_to_null($ldap, $query)
    {
        $this->beConstructedWith($ldap, array_merge($this->options, ['default_role' => null]));

        $query->getResult()->willReturn(new LdapObjectCollection(new LdapObject(['name' => 'Test'])));

        $this->setRoles($this->user)->getRoles()->shouldBeEqualTo([]);
    }

    function it_should_set_the_default_role($ldap)
    {
        $this->beConstructedWith($ldap, array_merge($this->options, ['default_role' => 'foobar']));

        $this->setRoles($this->user)->getRoles()->shouldContain('FOOBAR');
    }

    function it_should_not_query_ldap_if_no_roles_are_defined($ldap, $query)
    {
        $this->beConstructedWith($ldap, ['roles' => []]);

        $query->getResult()->shouldNotBeCalled();
        $this->setRoles($this->user);
    }
}
