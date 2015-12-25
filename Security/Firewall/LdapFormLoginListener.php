<?php
/**
 * This file is part of the LdapToolsBundle package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace LdapTools\Bundle\LdapToolsBundle\Security\Firewall;

use Symfony\Component\HttpFoundation\ParameterBag;
use Symfony\Component\Security\Http\ParameterBagUtils;
use Symfony\Component\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\Form\Extension\Csrf\CsrfProvider\CsrfProviderAdapter;
use Symfony\Component\Form\Extension\Csrf\CsrfProvider\CsrfProviderInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Kernel;
use Symfony\Component\Security\Core\Authentication\AuthenticationManagerInterface;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;
use Symfony\Component\Security\Core\Exception\InvalidArgumentException;
use Symfony\Component\Security\Core\Exception\InvalidCsrfTokenException;
use Symfony\Component\Security\Core\Security;
use Symfony\Component\Security\Core\SecurityContextInterface;
use Symfony\Component\Security\Csrf\CsrfToken;
use Symfony\Component\Security\Csrf\CsrfTokenManagerInterface;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Http\Authentication\AuthenticationFailureHandlerInterface;
use Symfony\Component\Security\Http\Authentication\AuthenticationSuccessHandlerInterface;
use Symfony\Component\Security\Http\Firewall\AbstractAuthenticationListener;
use Symfony\Component\Security\Http\HttpUtils;
use Symfony\Component\Security\Http\Session\SessionAuthenticationStrategyInterface;
use Psr\Log\LoggerInterface;

/**
 * The form login listener for LDAP authentication.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class LdapFormLoginListener extends AbstractAuthenticationListener
{
    /**
     * @var CsrfProviderAdapter|CsrfTokenManagerInterface|null
     */
    private $csrfTokenManager;

    /**
     * @var array
     */
    private $defaultListOpts = [
        'username_parameter' => '_username',
        'password_parameter' => '_password',
        'domain_parameter' => '_ldap_domain',
        'csrf_parameter' => '_csrf_token',
        'intention' => 'authenticate',
        'post_only' => true,
    ];

    /**
     * @param TokenStorageInterface|SecurityContextInterface $tokenStorage
     * @param AuthenticationManagerInterface $authenticationManager
     * @param SessionAuthenticationStrategyInterface $sessionStrategy
     * @param HttpUtils $httpUtils
     * @param string $providerKey
     * @param AuthenticationSuccessHandlerInterface $successHandler
     * @param AuthenticationFailureHandlerInterface $failureHandler
     * @param array $options
     * @param LoggerInterface $logger
     * @param EventDispatcherInterface $dispatcher
     * @param null $csrfTokenManager
     * @throws InvalidArgumentException|\InvalidArgumentException
     */
    public function __construct(
        $tokenStorage,
        AuthenticationManagerInterface $authenticationManager,
        SessionAuthenticationStrategyInterface $sessionStrategy,
        HttpUtils $httpUtils,
        $providerKey,
        AuthenticationSuccessHandlerInterface $successHandler,
        AuthenticationFailureHandlerInterface $failureHandler,
        array $options = [],
        LoggerInterface $logger = null,
        EventDispatcherInterface $dispatcher = null,
        $csrfTokenManager = null
    ) {
        // Requires some additional logic for BC...
        $csrfTokenManager = $this->getCsrfManager($csrfTokenManager);

        // TokenStorageInterface is Symfony 2.6 and onwards...
        if (!($tokenStorage instanceof TokenStorageInterface || $tokenStorage instanceof  SecurityContextInterface)) {
            $this->throwInvalidArgumentException('The first argument should be an instance of SecurityContext or TokenStorage.');
        }

        parent::__construct(
            $tokenStorage,
            $authenticationManager,
            $sessionStrategy,
            $httpUtils,
            $providerKey,
            $successHandler,
            $failureHandler,
            array_merge($this->defaultListOpts, $options),
            $logger,
            $dispatcher
        );
        $this->csrfTokenManager = $csrfTokenManager;
    }

    /**
     * {@inheritdoc}
     */
    protected function requiresAuthentication(Request $request)
    {
        if ($this->options['post_only'] && !$request->isMethod('POST')) {
            return false;
        }

        return parent::requiresAuthentication($request);
    }

    /**
     * {@inheritdoc}
     */
    protected function attemptAuthentication(Request $request)
    {
        $this->validateCsrfToken($request);

        return $this->authenticationManager->authenticate($this->getUsernamePasswordToken($request));
    }

    /**
     * Get the UsernamePasswordToken based off the Request parameters.
     *
     * @param Request $request
     * @return UsernamePasswordToken
     */
    protected function getUsernamePasswordToken(Request $request)
    {
        if ($this->options['post_only']) {
            $username = trim($this->getParameterFromBag($request->request, $this->options['username_parameter']));
            $password = $this->getParameterFromBag($request->request, $this->options['password_parameter']);
        } else {
            $username = trim($this->getParameterFromRequest($request, $this->options['username_parameter']));
            $password = $this->getParameterFromRequest($request, $this->options['password_parameter']);
        }
        $this->setLastUsernameInSession($request, $username);

        $token = new UsernamePasswordToken($username, $password, $this->providerKey);
        $this->addDomainToTokenIfPresent($request, $token);

        return $token;
    }

    /**
     * Add the domain name for the login request to the token if specified.
     *
     * @param Request $request
     * @param UsernamePasswordToken $token
     */
    protected function addDomainToTokenIfPresent(Request $request, UsernamePasswordToken $token)
    {
        if ($this->options['post_only'] && $request->request->has($this->options['domain_parameter'])) {
            $token->setAttribute(
                'ldap_domain',
                trim($this->getParameterFromBag($request->request, $this->options['domain_parameter']))
            );
        } elseif ($domain = trim($this->getParameterFromRequest($request, $this->options['domain_parameter']))) {
            $token->setAttribute('ldap_domain', $domain);
        }
    }

    /**
     * A BC wrapper to determine how to handle the CSRF parameter in the constructor.
     *
     * @param null|CsrfProviderInterface|CsrfTokenManagerInterface $csrf
     */
    protected function getCsrfManager($csrf)
    {
        if (Kernel::VERSION < '2.4') {
            if (!is_null($csrf) && !($csrf instanceof CsrfProviderInterface)) {
                // The Security Core InvalidArgumentException did not exist at this version.
                throw new \InvalidArgumentException('The CSRF provider must implement CsrfProviderInterface');
            }

            return $csrf;
        }

        if ($csrf instanceof CsrfProviderInterface) {
            $csrf = new CsrfProviderAdapter($csrf);
        } elseif (!is_null($csrf) && !($csrf instanceof CsrfTokenManagerInterface)) {
            throw new InvalidArgumentException('The CSRF token manager should be an instance of CsrfProviderInterface or CsrfTokenManagerInterface.');
        }

        return $csrf;
    }

    /**
     * Provide a BC wrapper for CSRF token manager/provider compatibility between versions.
     *
     * @param Request $request
     */
    protected function validateCsrfToken(Request $request)
    {
        if (is_null($this->csrfTokenManager)) {
            return;
        }
        $csrfToken = $this->getParameterFromRequest($request, $this->options['csrf_parameter']);

        if ($this->csrfTokenManager instanceof CsrfTokenManagerInterface) {
            if (false === $this->csrfTokenManager->isTokenValid(new CsrfToken($this->options['intention'], $csrfToken))) {
                throw new InvalidCsrfTokenException('Invalid CSRF token.');
            }
        }

        if ($this->csrfTokenManager instanceof CsrfProviderInterface) {
            if (false === $this->csrfTokenManager->isCsrfTokenValid($this->options['intention'], $csrfToken)) {
                throw new InvalidCsrfTokenException('Invalid CSRF token.');
            }
        }
    }

    /**
     * Provide a BC wrapper for deep item finding deprecation.
     *
     * @param Request $request
     * @param string $param
     * @return mixed
     */
    protected function getParameterFromRequest(Request $request, $param)
    {
        if (!$this->useParameterBagUtils()) {
            return $request->get($param, null, true);
        }

        return ParameterBagUtils::getRequestParameterValue($request, $param);
    }

    /**
     * Provide a BC wrapper for deep item finding deprecation.
     *
     * @param ParameterBag $bag
     * @param string $param
     * @return mixed
     */
    protected function getParameterFromBag($bag, $param)
    {
        if (!$this->useParameterBagUtils()) {
            return $bag->get($param, null, true);
        }

        return ParameterBagUtils::getParameterBagValue($bag, $param);
    }

    /**
     * Whether or not the ParameterBagUtils class exists (2.8 and above...)
     *
     * @return bool
     */
    protected function useParameterBagUtils()
    {
        return class_exists('Symfony\Component\Security\Http\ParameterBagUtils');
    }

    /**
     * Yet another BC wrapper to account for changes in the way that the last username is set in the session.
     *
     * @param Request $request
     * @param string $username
     */
    protected function setLastUsernameInSession(Request $request, $username)
    {
        // Security class only exists post Symfony 2.6 and onwards...
        if (class_exists('\Symfony\Component\Security\Core\Security')) {
            $request->getSession()->set(Security::LAST_USERNAME, $username);
        } else {
            $request->getSession()->set(SecurityContextInterface::LAST_USERNAME, $username);
        }
    }

    /**
     * Another BC wrapper since the security core invalid argument exception did not exist early on.
     *
     * @param string $message
     * @throws InvalidArgumentException|\InvalidArgumentException
     */
    protected function throwInvalidArgumentException($message)
    {
        if (class_exists('\Symfony\Component\Security\Core\Exception\InvalidArgumentException')) {
            throw new InvalidArgumentException($message);
        } else {
            throw new \InvalidArgumentException($message);
        }
    }
}
