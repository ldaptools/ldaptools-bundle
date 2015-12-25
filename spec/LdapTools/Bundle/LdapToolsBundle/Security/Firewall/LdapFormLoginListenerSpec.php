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
use Prophecy\Argument;
use Psr\Log\LoggerInterface;
use Symfony\Component\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\HttpKernel\Kernel;
use Symfony\Component\Security\Core\Authentication\AuthenticationManagerInterface;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Csrf\CsrfTokenManagerInterface;
use Symfony\Component\Security\Http\Authentication\AuthenticationFailureHandlerInterface;
use Symfony\Component\Security\Http\Authentication\AuthenticationSuccessHandlerInterface;
use Symfony\Component\Security\Http\HttpUtils;
use Symfony\Component\Security\Http\Session\SessionAuthenticationStrategyInterface;

class LdapFormLoginListenerSpec extends ObjectBehavior
{
    /**
     * @var HttpUtils
     */
    protected $httpUtils;

    /**
     * @var AuthenticationManagerInterface
     */
    protected $authManager;

    /**
     * @var TokenStorageInterface
     */
    protected $tokenStorage;

    /**
     * @var SessionAuthenticationStrategyInterface
     */
    protected $authStrategy;

    /**
     * @var AuthenticationSuccessHandlerInterface
     */
    protected $authSuccess;

    /**
     * @var AuthenticationFailureHandlerInterface
     */
    protected $authFailure;

    /**
     * @var EventDispatcherInterface
     */
    protected $eventDispatcher;

    /**
     * @var LoggerInterface
     */
    protected $logger;

    /**
     * @var CsrfTokenManagerInterface
     */
    protected $tokenManager;

    /**
     * @param \Symfony\Component\Security\Core\Authentication\AuthenticationManagerInterface $authManager
     * @param \Symfony\Component\Security\Http\Session\SessionAuthenticationStrategyInterface $authStrategy
     * @param \Symfony\Component\Security\Http\HttpUtils $httpUtils
     * @param \Symfony\Component\Security\Http\Authentication\AuthenticationSuccessHandlerInterface $authSuccess
     * @param \Symfony\Component\Security\Http\Authentication\AuthenticationFailureHandlerInterface $authFailure
     * @param \Psr\Log\LoggerInterface $logger
     * @param \Symfony\Component\EventDispatcher\EventDispatcherInterface $eventDispatcher
     */
    function let($authManager, $authStrategy, $httpUtils, $authSuccess, $authFailure, $logger, $eventDispatcher, $csrfTokenManager, $tokenStorage)
    {
        if (Kernel::VERSION > 2.6) {
            $csrfTokenManager->beADoubleOf('Symfony\Component\Security\Csrf\CsrfTokenManagerInterface');
            $tokenStorage->beADoubleOf('Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface');
        } else {
            $csrfTokenManager->beADoubleOf('Symfony\Component\Form\Extension\Csrf\CsrfProvider\CsrfProviderInterface');
            $tokenStorage->beADoubleOf('Symfony\Component\Security\Core\SecurityContextInterface');
        }

        $this->httpUtils = $httpUtils;
        $this->authManager = $authManager;
        $this->authManager = $authManager;
        $this->authStrategy = $authStrategy;
        $this->authSuccess = $authSuccess;
        $this->authFailure = $authFailure;
        $this->logger = $logger;
        $this->eventDispatcher = $eventDispatcher;
        $this->tokenManager = $csrfTokenManager;
        $this->tokenStorage = $tokenStorage;

        $this->beConstructedWith(
            $this->tokenStorage,
            $this->authManager,
            $this->authStrategy,
            $this->httpUtils,
            'restricted',
            $this->authSuccess,
            $this->authFailure,
            [],
            $this->logger,
            $this->eventDispatcher,
            $this->tokenManager
        );
    }

    function it_is_initializable()
    {
        $this->shouldHaveType('LdapTools\Bundle\LdapToolsBundle\Security\Firewall\LdapFormLoginListener');
    }

    function it_should_only_support_token_storage_or_security_context_in_the_construct()
    {
        $this->beConstructedWith(
            [new \DateTime(),
            $this->authManager,
            $this->authStrategy,
            $this->httpUtils,
            'restricted',
            $this->authSuccess,
            $this->authFailure,
            [],
            $this->logger,
            $this->eventDispatcher,
            $this->tokenManager]
        );

        if (Kernel::VERSION < '2.4') {
            $e = '\InvalidArgumentException';
        } else {
            $e = '\Symfony\Component\Security\Core\Exception\InvalidArgumentException';
        }

        $this->shouldThrow($e)->during('__construct', [
            new \DateTime(),
            $this->authManager,
            $this->authStrategy,
            $this->httpUtils,
            'restricted',
            $this->authSuccess,
            $this->authFailure,
            [],
            $this->logger,
            $this->eventDispatcher,
            $this->tokenManager
        ]);
    }
}
