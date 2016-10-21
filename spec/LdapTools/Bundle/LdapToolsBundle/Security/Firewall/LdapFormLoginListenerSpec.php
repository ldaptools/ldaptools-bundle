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
use Symfony\Component\HttpKernel\Kernel;
use Symfony\Component\Security\Core\Authentication\AuthenticationManagerInterface;
use Symfony\Component\Security\Http\Authentication\AuthenticationFailureHandlerInterface;
use Symfony\Component\Security\Http\Authentication\AuthenticationSuccessHandlerInterface;
use Symfony\Component\Security\Http\HttpUtils;
use Symfony\Component\Security\Http\Session\SessionAuthenticationStrategyInterface;

class LdapFormLoginListenerSpec extends ObjectBehavior
{
    function let(AuthenticationManagerInterface $authManager, SessionAuthenticationStrategyInterface $authStrategy, HttpUtils $httpUtils, AuthenticationSuccessHandlerInterface $authSuccess, AuthenticationFailureHandlerInterface $authFailure, LoggerInterface $logger, EventDispatcherInterface $eventDispatcher, $csrfTokenManager, $tokenStorage)
    {
        if (Kernel::VERSION > 2.6) {
            $csrfTokenManager->beADoubleOf('Symfony\Component\Security\Csrf\CsrfTokenManagerInterface');
            $tokenStorage->beADoubleOf('Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface');
        } else {
            $csrfTokenManager->beADoubleOf('Symfony\Component\Form\Extension\Csrf\CsrfProvider\CsrfProviderInterface');
            $tokenStorage->beADoubleOf('Symfony\Component\Security\Core\SecurityContextInterface');
        }

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

    function it_should_only_support_token_storage_or_security_context_in_the_construct($authManager, $authStrategy, $httpUtils, $authSuccess, $authFailure, $logger, $eventDispatcher, $csrfTokenManager)
    {
        $this->beConstructedWith(
            [new \DateTime(),
            $authManager,
            $authStrategy,
            $httpUtils,
            'restricted',
            $authSuccess,
            $authFailure,
            [],
            $logger,
            $eventDispatcher,
            $csrfTokenManager]
        );

        if (Kernel::VERSION < '2.4') {
            $e = '\InvalidArgumentException';
        } else {
            $e = '\Symfony\Component\Security\Core\Exception\InvalidArgumentException';
        }

        $this->shouldThrow($e)->during('__construct', [
            new \DateTime(),
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
        ]);
    }
}
