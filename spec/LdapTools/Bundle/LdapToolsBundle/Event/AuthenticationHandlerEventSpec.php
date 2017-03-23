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

use LdapTools\Bundle\LdapToolsBundle\Event\AuthenticationHandlerEvent;
use PhpSpec\ObjectBehavior;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;

class AuthenticationHandlerEventSpec extends ObjectBehavior
{
    function let(RedirectResponse $redirectResponse, Request $request)
    {
        $this->beConstructedWith($redirectResponse, $request);
    }

    function it_is_initializable()
    {
        $this->shouldHaveType(AuthenticationHandlerEvent::class);
    }

    function it_should_set_and_get_the_response($redirectResponse)
    {
        $newResponse = new RedirectResponse('/foo');

        $this->getResponse()->shouldBeEqualTo($redirectResponse);
        $this->setResponse($newResponse)->getResponse()->shouldBeEqualTo($newResponse);
    }

    function it_should_be_constructed_with_an_exception_provider_key_and_token($redirectResponse, $request, TokenInterface $token)
    {
        $exception = new \Exception('foo');
        $this->beConstructedWith($redirectResponse, $request, $exception, $token, 'foo');

        $this->getToken()->shouldBeEqualTo($token);
        $this->getRequest()->shouldBeEqualTo($request);
        $this->getProviderKey()->shouldBeEqualTo('foo');
        $this->getException()->shouldBeEqualTo($exception);
    }
}
