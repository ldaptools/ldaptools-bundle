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
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\Authentication\AuthenticationManagerInterface;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;
use Symfony\Component\Security\Core\Exception\InvalidCsrfTokenException;
use Symfony\Component\Security\Core\Security;
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
     * @var CsrfTokenManagerInterface|null
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
     * @param TokenStorageInterface $tokenStorage
     * @param AuthenticationManagerInterface $authenticationManager
     * @param SessionAuthenticationStrategyInterface $sessionStrategy
     * @param HttpUtils $httpUtils
     * @param string $providerKey
     * @param AuthenticationSuccessHandlerInterface $successHandler
     * @param AuthenticationFailureHandlerInterface $failureHandler
     * @param array $options
     * @param LoggerInterface $logger
     * @param EventDispatcherInterface $dispatcher
     * @param null|CsrfTokenManagerInterface $csrfTokenManager
     */
    public function __construct(
        TokenStorageInterface $tokenStorage,
        AuthenticationManagerInterface $authenticationManager,
        SessionAuthenticationStrategyInterface $sessionStrategy,
        HttpUtils $httpUtils,
        $providerKey,
        AuthenticationSuccessHandlerInterface $successHandler,
        AuthenticationFailureHandlerInterface $failureHandler,
        array $options = [],
        LoggerInterface $logger = null,
        EventDispatcherInterface $dispatcher = null,
        CsrfTokenManagerInterface $csrfTokenManager = null
    ) {
        $this->csrfTokenManager = $csrfTokenManager;

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
        $request->getSession()->set(Security::LAST_USERNAME, $username);

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

        if (false === $this->csrfTokenManager->isTokenValid(new CsrfToken($this->options['intention'], $csrfToken))) {
            throw new InvalidCsrfTokenException('Invalid CSRF token.');
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
}
