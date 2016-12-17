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

use LdapTools\Bundle\LdapToolsBundle\Event\LoadUserEvent;
use LdapTools\Bundle\LdapToolsBundle\Security\User\LdapUser;
use LdapTools\Connection\LdapConnectionInterface;
use LdapTools\DomainConfiguration;
use LdapTools\Exception\EmptyResultException;
use LdapTools\Exception\MultiResultException;
use LdapTools\LdapManager;
use LdapTools\Object\LdapObjectCollection;
use LdapTools\Object\LdapObjectType;
use LdapTools\Query\Builder\ADFilterBuilder;
use LdapTools\Query\LdapQuery;
use LdapTools\Query\LdapQueryBuilder;
use PhpSpec\ObjectBehavior;
use Prophecy\Argument;
use LdapTools\Object\LdapObject;
use Symfony\Component\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\Security\Core\User\User;

class LdapUserProviderSpec extends ObjectBehavior
{
    protected $attr = [
        'username' => 'foo',
        'guid' => '26dc475e-aca2-4b45-b3ad-5a2c73d4f8c5',
        'locked' => false,
        'accountExpirationDate' => false,
        'enabled' => true,
        'passwordMustChange' => false,
        'groups' => ['foo', 'bar'],
        'dn' => 'cn=foo,dc=foo,dc=bar',
    ];

    function let(LdapManager $ldap, LdapQueryBuilder $qb, LdapQuery $query, LdapConnectionInterface $connection, EventDispatcherInterface $dispatcher)
    {
        $groups = new LdapObjectCollection();
        $groups->add(new LdapObject(['name' => 'Foo', 'dn' => 'cn=Foo,dc=example,dc=local']));
        $groups->add(new LdapObject(['guid' => '291d8444-9d5b-4b0a-a6d7-853408f704d5', 'dn' => 'cn=Bar,dc=example,dc=local']));
        $groups->add(new LdapObject(['sid' => 'S-1-5-18', 'dn' => 'cn=LocalSys,dc=example,dc=local']));
        $groups->add(new LdapObject(['name' => 'Just a DN', 'dn' => 'cn=Stuff,dc=example,dc=local']));
        $roleMap = [
            'ROLE_AWESOME' => ['foo'],
            'ROLE_ADMIN' => ['291d8444-9d5b-4b0a-a6d7-853408f704d5'],
            'ROLE_DN' => ['cn=Stuff,dc=example,dc=local'],
            'ROLE_SID' => ['S-1-5-18'],
        ];
        $config = new DomainConfiguration('foo.bar');
        $filter = new ADFilterBuilder();

        $ldapObject = new LdapObject($this->attr, 'user');
        $query->getSingleResult()->willReturn($ldapObject);
        $query->getResult()->willReturn($groups);
        $query->getArrayResult()->willReturn([
            ['name' => 'foo'],
            ['name' => 'bar'],
        ]);

        $qb->from(LdapObjectType::USER)->willReturn($qb);
        $qb->from('group')->willReturn($qb);
        $qb->select(["username", "guid", "accountExpirationDate", "enabled", "groups", "locked", "passwordMustChange"])->willReturn($qb);
        $qb->select(["name", "sid", "guid"])->willReturn($qb);
        $qb->select('name')->willReturn($qb);
        $qb->where(['username' => 'foo'])->willReturn($qb);
        $qb->getLdapQuery()->willReturn($query);
        $qb->filter()->willReturn($filter);
        $qb->where($filter->hasMemberRecursively($this->attr['guid'], 'members'))->willReturn($qb);
        $ldap->buildLdapQuery()->willReturn($qb);
        $ldap->getDomainContext()->willReturn('foo.bar');

        $connection->getConfig()->willReturn($config);
        $ldap->getConnection()->willReturn($connection);

        $this->beConstructedWith($ldap, $dispatcher, $roleMap, true);
    }

    function it_is_initializable()
    {
        $this->shouldHaveType('LdapTools\Bundle\LdapToolsBundle\Security\User\LdapUserProvider');
    }

    function it_should_load_by_username($dispatcher)
    {
        $dispatcher->dispatch(LoadUserEvent::BEFORE, Argument::type('\LdapTools\Bundle\LdapToolsBundle\Event\LoadUserEvent'))->shouldBeCalledTimes(1);
        $dispatcher->dispatch(LoadUserEvent::AFTER, Argument::type('\LdapTools\Bundle\LdapToolsBundle\Event\LoadUserEvent'))->shouldBeCalledTimes(1);

        $this->loadUserByUsername('foo')->shouldBeAnInstanceOf('\LdapTools\Bundle\LdapToolsBundle\Security\User\LdapUser');
    }

    function it_should_set_the_default_role()
    {
        $this->setDefaultRole('foobar');

        $this->loadUserByUsername('foo')->getRoles()->shouldContain('FOOBAR');
    }

    function it_should_not_set_a_default_role_if_it_is_set_to_null($query)
    {
        $this->setDefaultRole(null);
        $query->getResult()->willReturn(new LdapObjectCollection(new LdapObject(['name' => 'Test'])));

        $this->loadUserByUsername('foo')->getRoles()->shouldBeEqualTo([]);
    }

    function it_should_set_the_roles_properly_for_the_returned_groups($query)
    {
        $this->loadUserByUsername('foo')->getRoles()->shouldBeEqualTo(['ROLE_AWESOME', 'ROLE_ADMIN', 'ROLE_DN', 'ROLE_SID']);

        $query->getResult()->willReturn(new LdapObjectCollection(new LdapObject(['name' => 'foo'])));

        $this->loadUserByUsername('foo')->getRoles()->shouldBeEqualTo(['ROLE_AWESOME']);

        $query->getResult()->willReturn(new LdapObjectCollection(new LdapObject(['name' => 'foo.bar'])));

        $this->loadUserByUsername('foo')->getRoles()->shouldBeEqualTo([]);
    }

    /**
     * No easy way to spec this at the moment unfortunately.
     */
    function it_should_set_the_ldap_user_class()
    {
        $this->setUserClass('\LdapTools\Bundle\LdapToolsBundle\Security\User\LdapUser');
        $this->shouldThrow('\Exception')->duringSetUserClass('foo');
    }

    function it_should_set_additional_attributes_to_select($qb)
    {
        $this->setAttributes(['foo']);
        $qb->select(["username", "guid", "accountExpirationDate", "enabled", "groups", "locked", "passwordMustChange", "foo"])
            ->shouldBeCalled()->willReturn($qb);

        $this->loadUserByUsername('foo')->shouldBeAnInstanceOf('\LdapTools\Bundle\LdapToolsBundle\Security\User\LdapUser');
    }

    function it_should_refresh_a_user_by_their_guid($qb, LdapUser $user)
    {
        $user->getRoles()->willReturn(['ROLE_USER']);
        $user->getLdapGuid()->shouldBeCalled()->willReturn($this->attr['guid']);
        $qb->where(['guid' => $this->attr['guid']])->shouldBeCalled()->willReturn($qb);

        $this->refreshUser($user)->shouldBeAnInstanceOf('\LdapTools\Bundle\LdapToolsBundle\Security\User\LdapUser');
    }

    function it_should_not_refresh_a_user_it_cannot_support()
    {
        $this->shouldThrow('\Symfony\Component\Security\Core\Exception\UnsupportedUserException')
            ->duringRefreshUser(new User('foo', 'bar'));
    }

    function it_should_support_classes_that_extend_LdapUser()
    {
        $this->supportsClass('\LdapTools\Bundle\LdapToolsBundle\Security\User\LdapUser')->shouldBeEqualTo(true);
        $this->supportsClass('\Symfony\Component\Security\Core\User\User')->shouldBeEqualTo(false);
    }

    function it_should_throw_a_user_not_found_exception_if_no_user_is_returned_from_ldap($query)
    {
        $query->getSingleResult()->willThrow(new EmptyResultException());

        $this->shouldThrow('\Symfony\Component\Security\Core\Exception\UsernameNotFoundException')
            ->duringLoadUserByUsername('foo');
    }

    function it_should_throw_a_user_not_found_exception_if_too_many_results_are_returned_from_ldap($query)
    {
        $query->getSingleResult()->willThrow(new MultiResultException());

        $this->shouldThrow('\Symfony\Component\Security\Core\Exception\UsernameNotFoundException')
            ->duringLoadUserByUsername('foo');
    }

    function it_should_be_able_to_set_the_ldap_object_type_to_use_for_the_search($qb)
    {
        $this->setLdapObjectType('foobar');
        $qb->from('foobar')->shouldBeCalled()->willReturn($qb);

        $this->loadUserByUsername('foo');
    }

    function it_should_be_able_to_set_the_ldap_search_base_when_searching_for_the_user($qb)
    {
        $searchBase = 'ou=employees,dc=foo,dc=bar';
        $this->setSearchBase($searchBase);
        $qb->setBaseDn($searchBase)->shouldBeCalled()->willReturn($qb);

        $this->loadUserByUsername('foo');
    }
    
    function it_should_set_the_ldap_type_for_the_role_query($qb)
    {
        $this->setRoleLdapType('foo');
        $qb->from('foo')->shouldBeCalled()->willReturn($qb);

        $this->loadUserByUsername('foo');
    }

    function it_should_set_the_attribute_map_for_the_role_query($qb)
    {
        $this->setRoleAttributeMap(['members' => 'members', 'name' => 'cn', 'guid' => 'foo', 'sid' => 'bar']);
        $qb->select(['cn', 'foo', 'bar'])->shouldBeCalled()->willReturn($qb);

        $this->loadUserByUsername('foo');
    }

    function it_should_not_query_ldap_on_a_refresh_if_refresh_attributes_and_roles_is_false($connection, LdapUser $user)
    {
        $user->getRoles()->willReturn([]);
        $user->setRoles([])->shouldBeCalled();
        $this->setRefreshAttributes(false);
        $this->setRefreshRoles(false);
        $connection->execute(Argument::any())->shouldNotBeCalled();

        $this->refreshUser($user)->shouldBeEqualTo($user);
    }

    function it_should_refresh_attributes_but_not_roles_if_specified($query, LdapUser $user, $qb)
    {
        $this->setRefreshRoles(false);
        $query->getSingleResult()->shouldBeCalled();
        $query->getResult()->shouldNotBeCalled();

        $user->getLdapGuid()->shouldBeCalled()->willReturn($this->attr['guid']);
        $qb->where(['guid' => $this->attr['guid']])->shouldBeCalled()->willReturn($qb);
        $user->getRoles()->willReturn(['ROLE_USER']);

        $this->refreshUser($user)->toArray()->shouldBeEqualTo($this->attr);
        $this->refreshUser($user)->getRoles()->shouldBeEqualTo(['ROLE_USER']);
    }

    function it_should_refresh_roles_but_not_attributes_if_specified($query, LdapUser $user)
    {
        $this->setRefreshAttributes(false);
        $query->getResult()->shouldBeCalled();
        $user->getLdapGuid()->shouldBeCalled()->willReturn($this->attr['guid']);
        $user->getRoles()->willReturn(['ROLE_USER']);
        $query->getSingleResult()->shouldNotBeCalled();
        $user->setRoles(["ROLE_AWESOME", "ROLE_ADMIN", "ROLE_DN", "ROLE_SID"])->shouldBeCalled();

        $this->refreshUser($user);
    }
}
