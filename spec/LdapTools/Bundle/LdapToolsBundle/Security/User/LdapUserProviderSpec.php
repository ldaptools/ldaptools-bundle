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
use LdapTools\Bundle\LdapToolsBundle\Security\User\LdapRoleMapper;
use LdapTools\Bundle\LdapToolsBundle\Security\User\LdapUser;
use LdapTools\Connection\LdapConnectionInterface;
use LdapTools\DomainConfiguration;
use LdapTools\Exception\EmptyResultException;
use LdapTools\Exception\MultiResultException;
use LdapTools\LdapManager;
use LdapTools\Object\LdapObject;
use LdapTools\Object\LdapObjectType;
use LdapTools\Query\LdapQuery;
use LdapTools\Query\LdapQueryBuilder;
use PhpSpec\ObjectBehavior;
use Prophecy\Argument;
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

    function let(LdapManager $ldap, LdapQueryBuilder $qb, LdapQuery $query, LdapConnectionInterface $connection, EventDispatcherInterface $dispatcher, LdapRoleMapper $roleMapper)
    {
        $config = new DomainConfiguration('foo.bar');

        $ldapObject = new LdapObject($this->attr, 'user');
        $query->getSingleResult()->willReturn($ldapObject);
        $query->getArrayResult()->willReturn([
            ['name' => 'foo'],
            ['name' => 'bar'],
        ]);

        $qb->from(LdapObjectType::USER)->willReturn($qb);
        $qb->select(["username", "guid", "accountExpirationDate", "enabled", "groups", "locked", "passwordMustChange"])->willReturn($qb);
        $qb->select('name')->willReturn($qb);
        $qb->where(['username' => 'foo'])->willReturn($qb);
        $qb->getLdapQuery()->willReturn($query);
        $ldap->buildLdapQuery()->willReturn($qb);
        $ldap->getDomainContext()->willReturn('foo.bar');

        $connection->getConfig()->willReturn($config);
        $ldap->getConnection()->willReturn($connection);

        $this->beConstructedWith($ldap, $dispatcher, $roleMapper, []);
    }

    function it_is_initializable()
    {
        $this->shouldHaveType('LdapTools\Bundle\LdapToolsBundle\Security\User\LdapUserProvider');
    }

    function it_should_load_by_username($dispatcher)
    {
        $dispatcher->dispatch(Argument::type('\LdapTools\Bundle\LdapToolsBundle\Event\LoadUserEvent'), LoadUserEvent::BEFORE)->shouldBeCalledTimes(1);
        $dispatcher->dispatch(Argument::type('\LdapTools\Bundle\LdapToolsBundle\Event\LoadUserEvent'), LoadUserEvent::AFTER)->shouldBeCalledTimes(1);

        $this->loadUserByUsername('foo')->shouldBeAnInstanceOf('\LdapTools\Bundle\LdapToolsBundle\Security\User\LdapUser');
    }

    function it_should_set_the_ldap_user_class($ldap, $dispatcher, $roleMapper)
    {
        $this->beConstructedWith($ldap, $dispatcher, $roleMapper, ['user' => '\Foo']);

        $this->shouldThrow('Symfony\Component\Security\Core\Exception\UnsupportedUserException')->duringLoadUserByUsername('foo');
    }

    function it_should_set_additional_attributes_to_select($ldap, $dispatcher, $roleMapper, $qb)
    {
        $this->beConstructedWith($ldap, $dispatcher, $roleMapper, ['additional_attributes' => ['foo']]);

        $qb->select(["username", "guid", "accountExpirationDate", "enabled", "groups", "locked", "passwordMustChange", "foo"])
            ->shouldBeCalled()->willReturn($qb);

        $this->loadUserByUsername('foo')->shouldBeAnInstanceOf('\LdapTools\Bundle\LdapToolsBundle\Security\User\LdapUser');
    }

    function it_should_refresh_a_user_by_their_guid($qb, LdapUser $user, $ldap, $dispatcher, $roleMapper)
    {
        $this->beConstructedWith($ldap, $dispatcher, $roleMapper, ['refresh_user_attributes' => true]);

        $user->getRoles()->willReturn(['ROLE_USER']);
        $user->setRoles(['ROLE_USER'])->willReturn($user);
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

    function it_should_be_able_to_set_the_ldap_object_type_to_use_for_the_search($ldap, $dispatcher, $roleMapper, $qb)
    {
        $this->beConstructedWith($ldap, $dispatcher, $roleMapper, ['ldap_object_type' => 'foobar']);

        $qb->from('foobar')->shouldBeCalled()->willReturn($qb);

        $this->loadUserByUsername('foo');
    }

    function it_should_be_able_to_set_the_ldap_search_base_when_searching_for_the_user($ldap, $dispatcher, $roleMapper, $qb)
    {
        $this->beConstructedWith($ldap, $dispatcher, $roleMapper, ['search_base' => 'ou=employees,dc=foo,dc=bar']);

        $qb->setBaseDn('ou=employees,dc=foo,dc=bar')->shouldBeCalled()->willReturn($qb);

        $this->loadUserByUsername('foo');
    }

    function it_should_not_query_ldap_on_a_refresh_if_refresh_attributes_and_roles_is_false($connection, LdapUser $user, $roleMapper, $ldap, $dispatcher)
    {
        $this->beConstructedWith($ldap, $dispatcher, $roleMapper, ['refresh_user_roles' => false, 'refresh_user_attributes' => false]);

        $user->getRoles()->willReturn([]);
        $user->setRoles([])->shouldBeCalled();
        $connection->execute(Argument::any())->shouldNotBeCalled();
        $roleMapper->setRoles(Argument::any())->shouldNotBeCalled();

        $this->refreshUser($user)->shouldBeEqualTo($user);
    }

    function it_should_refresh_attributes_but_not_roles_if_specified($query, LdapUser $user, $qb, $roleMapper, $ldap, $dispatcher)
    {
        $this->beConstructedWith($ldap, $dispatcher, $roleMapper, ['refresh_user_roles' => false, 'refresh_user_attributes' => true]);

        $query->getSingleResult()->shouldBeCalled();
        $roleMapper->setRoles(Argument::any())->shouldNotBeCalled();

        $user->getLdapGuid()->shouldBeCalled()->willReturn($this->attr['guid']);
        $qb->where(['guid' => $this->attr['guid']])->shouldBeCalled()->willReturn($qb);
        $user->getRoles()->willReturn(['ROLE_USER']);

        $this->refreshUser($user)->toArray()->shouldBeEqualTo($this->attr);
        $this->refreshUser($user)->getRoles()->shouldBeEqualTo(['ROLE_USER']);
    }

    function it_should_refresh_roles_but_not_attributes_if_specified($query, LdapUser $user, $roleMapper, $ldap, $dispatcher)
    {
        $this->beConstructedWith($ldap, $dispatcher, $roleMapper, ['refresh_user_roles' => true, 'refresh_user_attributes' => false]);

        $user->getRoles()->willReturn(['ROLE_USER']);
        $query->getSingleResult()->shouldNotBeCalled();
        $roleMapper->setRoles($user)->shouldBeCalled();

        $this->refreshUser($user);
    }

    function it_should_get_a_ldap_user_object_from_a_specific_attribute_and_value()
    {
        $this->getLdapUser('username', 'foo')->shouldBeAnInstanceOf('LdapTools\Object\LdapObject');
    }
}
