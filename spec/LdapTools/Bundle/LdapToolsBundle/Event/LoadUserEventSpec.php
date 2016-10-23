<?php
/**
 * This file is part of the LdapToolsBundle package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace spec\LdapTools\Bundle\LdapToolsBundle\Event;

use LdapTools\Bundle\LdapToolsBundle\Event\LoadUserEvent;
use PhpSpec\ObjectBehavior;
use Symfony\Component\Security\Core\User\UserInterface;

class LoadUserEventSpec extends ObjectBehavior
{
    function let()
    {
        $this->beConstructedWith('foo', 'example.local');
    }

    function it_is_initializable()
    {
        $this->shouldHaveType(LoadUserEvent::class);
    }

    function the_user_should_be_null_by_default()
    {
        $this->getUser()->shouldBeNull();
    }

    function it_should_get_the_username()
    {
        $this->getUsername()->shouldEqual('foo');
    }

    function it_should_get_the_domain()
    {
        $this->getDomain()->shouldEqual('example.local');
    }

    function it_should_allow_being_constructed_with_a_user(UserInterface $user)
    {
        $this->beConstructedWith('foo', 'example.local', $user);

        $this->getUser()->shouldBeEqualTo($user);
    }
}
