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

use LdapTools\Bundle\LdapToolsBundle\Security\User\LdapUser;
use LdapTools\Object\LdapObject;
use PhpSpec\ObjectBehavior;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;

class LdapLoginEventSpec extends ObjectBehavior
{
    function let(TokenInterface $token)
    {
        $this->beConstructedWith(new LdapUser(new LdapObject(['foo' =>'bar'])), $token);
    }

    function it_is_initializable()
    {
        $this->shouldHaveType('LdapTools\Bundle\LdapToolsBundle\Event\LdapLoginEvent');
    }
    
    function it_should_get_the_user()
    {
        $this->getUser()->shouldReturnAnInstanceOf('LdapTools\Bundle\LdapToolsBundle\Security\User\LdapUser');
    }

    function it_should_get_the_token($token)
    {
        $this->getToken()->shouldBeEqualTo($token);
    }
}
