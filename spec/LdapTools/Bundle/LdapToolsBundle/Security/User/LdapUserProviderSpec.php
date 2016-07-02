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
use Symfony\Component\Security\Core\User\User;

class LdapUserProviderSpec extends ObjectBehavior
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
     * @var LdapConnectionInterface
     */
    protected $connection;

    /**
     * @var DomainConfiguration
     */
    protected $config;

    /**
     * @var ADFilterBuilder
     */
    protected $filter;

    /**
     * @var LdapObject
     */
    protected $ldapObject;

    protected $attr = [
        'username' => 'foo',
        'locked' => false,
        'accountExpirationDate' => false,
        'disabled' => false,
        'passwordMustChange' => false,
        'guid' => '26dc475e-aca2-4b45-b3ad-5a2c73d4f8c5',
        'groups' => ['foo', 'bar']
    ];

    /**
     * @param \LdapTools\LdapManager $ldap
     * @param \LdapTools\Query\LdapQueryBuilder $qb
     * @param \LdapTools\Query\LdapQuery $query
     * @param \LdapTools\Connection\LdapConnectionInterface $connection
     */
    function let($ldap, $qb, $query, $connection)
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
        $attrMap = [
            'username' => 'username',
            'accountNonLocked' => 'locked',
            'accountNonExpired' => 'accountExpirationDate',
            'enabled' => 'disabled',
            'credentialsNonExpired' => 'passwordMustChange',
            'guid' => 'guid',
            'groups' => 'groups',
            'stringRepresentation' => 'username',
        ];
        $this->ldap = $ldap;
        $this->qb = $qb;
        $this->query = $query;
        $this->connection = $connection;
        $this->config = new DomainConfiguration('foo.bar');
        $this->filter = new ADFilterBuilder();

        $this->ldapObject = new LdapObject($this->attr, ['user'], ['user'], 'user');
        $query->getSingleResult()->willReturn($this->ldapObject);
        $query->getResult()->willReturn($groups);
        $query->getArrayResult()->willReturn([
            ['name' => 'foo'],
            ['name' => 'bar'],
        ]);

        $qb->from(LdapObjectType::USER)->willReturn($qb);
        $qb->from('group')->willReturn($qb);
        $qb->select(["username", "locked", "accountExpirationDate", "disabled", "passwordMustChange", "guid", "groups", "username"])->willReturn($qb);
        $qb->select(["name", "sid", "guid"])->willReturn($qb);
        $qb->select('name')->willReturn($qb);
        $qb->where(['username' => 'foo'])->willReturn($qb);
        $qb->getLdapQuery()->willReturn($query);
        $qb->filter()->willReturn($this->filter);
        $qb->where($this->filter->hasMemberRecursively($this->attr['guid'], 'members'))->willReturn($qb);
        $this->ldap->buildLdapQuery()->willReturn($qb);

        $connection->getConfig()->willReturn($this->config);
        $this->ldap->getConnection()->willReturn($connection);

        $this->beConstructedWith($ldap, $attrMap, $roleMap, true);
    }

    function it_is_initializable()
    {
        $this->shouldHaveType('LdapTools\Bundle\LdapToolsBundle\Security\User\LdapUserProvider');
    }

    function it_should_load_by_username()
    {
        $this->loadUserByUsername('foo')->shouldBeAnInstanceOf('\LdapTools\Bundle\LdapToolsBundle\Security\User\LdapUser');
    }

    function it_should_set_the_default_role()
    {
        $this->setDefaultRole('foobar');

        $this->loadUserByUsername('foo')->getRoles()->shouldContain('FOOBAR');
    }

    function it_should_not_set_a_default_role_if_it_is_set_to_null()
    {
        $this->setDefaultRole(null);
        $this->query->getResult()->willReturn(new LdapObjectCollection(new LdapObject(['name' => 'Test'])));

        $this->loadUserByUsername('foo')->getRoles()->shouldBeEqualTo([]);
    }

    function it_should_set_the_roles_properly_for_the_returned_groups()
    {
        $this->loadUserByUsername('foo')->getRoles()->shouldBeEqualTo(['ROLE_AWESOME', 'ROLE_ADMIN', 'ROLE_DN', 'ROLE_SID']);

        $this->query->getResult()->willReturn(new LdapObjectCollection(new LdapObject(['name' => 'foo'])));

        $this->loadUserByUsername('foo')->getRoles()->shouldBeEqualTo(['ROLE_AWESOME']);

        $this->query->getResult()->willReturn(new LdapObjectCollection(new LdapObject(['name' => 'foo.bar'])));

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

    function it_should_set_additional_attributes_to_select()
    {
        $this->setAttributes(['foo']);
        $this->qb->select(["username", "locked", "accountExpirationDate", "disabled", "passwordMustChange", "guid", "groups", "username", "foo"])
            ->shouldBeCalled()->willReturn($this->qb);

        $this->loadUserByUsername('foo')->shouldBeAnInstanceOf('\LdapTools\Bundle\LdapToolsBundle\Security\User\LdapUser');
    }

    /**
     * @param \LdapTools\Bundle\LdapToolsBundle\Security\User\LdapUser $user
     */
    function it_should_refresh_a_user_by_their_guid($user)
    {
        $user->getLdapGuid()->shouldBeCalled()->willReturn($this->attr['guid']);
        $this->qb->where(['guid' => $this->attr['guid']])->shouldBeCalled()->willReturn($this->qb);

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

    function it_should_throw_a_user_not_found_exception_if_no_user_is_returned_from_ldap()
    {
        $this->query->getSingleResult()->willThrow(new EmptyResultException());

        $this->shouldThrow('\Symfony\Component\Security\Core\Exception\UsernameNotFoundException')
            ->duringLoadUserByUsername('foo');
    }

    function it_should_throw_a_user_not_found_exception_if_too_many_results_are_returned_from_ldap()
    {
        $this->query->getSingleResult()->willThrow(new MultiResultException());

        $this->shouldThrow('\Symfony\Component\Security\Core\Exception\UsernameNotFoundException')
            ->duringLoadUserByUsername('foo');
    }

    function it_should_be_able_to_set_the_ldap_object_type_to_use_for_the_search()
    {
        $this->setLdapObjectType('foobar');
        $this->qb->from('foobar')->shouldBeCalled()->willReturn($this->qb);

        $this->loadUserByUsername('foo');
    }

    function it_should_be_able_to_set_the_ldap_search_base_when_searching_for_the_user()
    {
        $searchBase = 'ou=employees,dc=foo,dc=bar';
        $this->setSearchBase($searchBase);
        $this->qb->setBaseDn($searchBase)->shouldBeCalled()->willReturn($this->qb);

        $this->loadUserByUsername('foo');
    }
    
    function it_should_set_the_ldap_type_for_the_role_query()
    {
        $this->setRoleLdapType('foo');
        $this->qb->from('foo')->shouldBeCalled()->willReturn($this->qb);

        $this->loadUserByUsername('foo');
    }

    function it_should_set_the_attribute_map_for_the_role_query()
    {
        $this->setRoleAttributeMap(['members' => 'members', 'name' => 'cn', 'guid' => 'foo', 'sid' => 'bar']);
        $this->qb->select(['cn', 'foo', 'bar'])->shouldBeCalled()->willReturn($this->qb);

        $this->loadUserByUsername('foo');
    }
}
