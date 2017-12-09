<?php
/**
 * This file is part of the LdapToolsBundle package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace spec\LdapTools\Bundle\LdapToolsBundle\Security\Firewall;

use PhpSpec\ObjectBehavior;
use Psr\Log\LoggerInterface;
use Symfony\Component\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\Security\Core\Authentication\AuthenticationManagerInterface;
use Symfony\Component\Security\Csrf\CsrfTokenManagerInterface;
use Symfony\Component\Security\Csrf\TokenStorage\TokenStorageInterface;
use Symfony\Component\Security\Http\Authentication\AuthenticationFailureHandlerInterface;
use Symfony\Component\Security\Http\Authentication\AuthenticationSuccessHandlerInterface;
use Symfony\Component\Security\Http\HttpUtils;
use Symfony\Component\Security\Http\Session\SessionAuthenticationStrategyInterface;

class LdapFormLoginListenerSpec extends ObjectBehavior
{
    function let(AuthenticationManagerInterface $authManager, SessionAuthenticationStrategyInterface $authStrategy, HttpUtils $httpUtils, AuthenticationSuccessHandlerInterface $authSuccess, AuthenticationFailureHandlerInterface $authFailure, LoggerInterface $logger, EventDispatcherInterface $eventDispatcher, CsrfTokenManagerInterface $csrfTokenManager, TokenStorageInterface $tokenStorage)
    {
        $this->beConstructedWith(
            $tokenStorage,
            $authManager,
            $authStrategy,
            $httpUtils,
            'restricted',
            $authSuccess,
            $authFailure,
            [],
            $logger,
            $eventDispatcher,
            $csrfTokenManager
        );
    }

    function it_is_initializable()
    {
        $this->shouldHaveType('LdapTools\Bundle\LdapToolsBundle\Security\Firewall\LdapFormLoginListener');
    }
}
