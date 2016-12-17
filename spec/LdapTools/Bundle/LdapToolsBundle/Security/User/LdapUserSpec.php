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

use LdapTools\Object\LdapObject;
use PhpSpec\ObjectBehavior;

class LdapUserSpec extends ObjectBehavior
{
    function let()
    {
        $attributes = [
            'dn' => 'cn=chad,dc=foo,dc=bar',
            'username' => 'chad',
            'disabled' => false,
            'passwordMustChange' => false,
            'accountExpirationDate' => new \DateTime('2233-3-22'),
            'groups' => [
                'foo',
                'bar',
            ],
            'guid' => '39ff94c0-d84f-4b5d-9d63-94439e533949',
            'locked' => false
        ];
        $this->beConstructedWith();
        $this->refresh($attributes);
    }

    function it_is_initializable()
    {
        $this->shouldHaveType('LdapTools\Bundle\LdapToolsBundle\Security\User\LdapUser');
    }

    function it_should_implement_AdvancedUserInterface()
    {
        $this->shouldImplement('\Symfony\Component\Security\Core\User\AdvancedUserInterface');
    }

    function it_should_implement_Serializable()
    {
        $this->shouldImplement('\Serializable');
    }

    function it_should_get_the_username()
    {
        $this->getUsername()->shouldBeEqualTo('chad');
    }

    function it_should_get_the_enabled_status()
    {
        $this->isEnabled()->shouldBeEqualTo(true);
    }

    function it_should_get_the_locked_status()
    {
        $this->isAccountNonLocked()->shouldBeEqualTo(true);
    }

    function it_should_get_the_account_expiration_status()
    {
        $this->isAccountNonExpired()->shouldBeEqualTo(true);
    }

    function it_should_get_the_guid()
    {
        $this->getGuid()->shouldBeEqualTo('39ff94c0-d84f-4b5d-9d63-94439e533949');
    }

    function it_should_get_the_groups()
    {
        $this->getGroups()->shouldBeEqualTo(['foo','bar']);
    }

    function it_should_set_the_username()
    {
        $this->setUsername('foo');
        $this->getUsername()->shouldBeEqualTo('foo');
    }

    function it_should_return_null_for_salt()
    {
        $this->getSalt()->shouldBeNull();
    }

    function it_should_return_null_for_password()
    {
        $this->getPassword()->shouldBeNull();
    }

    function it_should_return_null_when_erasing_credentials()
    {
        $this->eraseCredentials()->shouldBeNull();
    }

    function it_should_have_no_roles_by_default()
    {
        $this->getRoles()->shouldHaveCount(0);
    }

    function it_should_add_roles_properly()
    {
        $this->addRole('foo');
        $this->getRoles()->shouldBeEqualTo(['FOO']);
        $this->addRole('BAR');
        $this->getRoles()->shouldBeEqualTo(['FOO', 'BAR']);
    }

    function it_should_set_roles_properly()
    {
        $this->addRole('meh');
        $this->setRoles(['foo','BAR']);
        $this->getRoles()->shouldBeEqualTo(['FOO', 'BAR']);
    }

    function it_should_have_a_string_representation_of_a_dn_by_default()
    {
        $this->__toString()->shouldBeEqualTo('chad');
    }
}
