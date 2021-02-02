<?php
/**
 * This file is part of the LdapToolsBundle package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace LdapTools\Bundle\LdapToolsBundle\Security;

use LdapTools\Bundle\LdapToolsBundle\Event\AuthenticationHandlerEvent;
use LdapTools\Bundle\LdapToolsBundle\Event\LdapLoginEvent;
use LdapTools\Bundle\LdapToolsBundle\Security\User\LdapUserChecker;
use LdapTools\Bundle\LdapToolsBundle\Security\User\LdapUserProvider;
use LdapTools\Exception\LdapConnectionException;
use LdapTools\Operation\AuthenticationOperation;
use LdapTools\LdapManager;
use Symfony\Component\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;
use Symfony\Component\Security\Core\Exception\CustomUserMessageAuthenticationException;
use Symfony\Component\Security\Core\Exception\UsernameNotFoundException;
use Symfony\Component\Security\Core\Security;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Guard\AbstractGuardAuthenticator;
use Symfony\Component\Security\Http\Authentication\AuthenticationFailureHandlerInterface;
use Symfony\Component\Security\Http\Authentication\AuthenticationSuccessHandlerInterface;
use Symfony\Component\Security\Http\EntryPoint\AuthenticationEntryPointInterface;
use Symfony\Component\Security\Http\EntryPoint\BasicAuthenticationEntryPoint;

/**
 * LDAP Guard Authenticator.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class LdapGuardAuthenticator extends AbstractGuardAuthenticator
{
    use LdapAuthenticationTrait;

    /**
     * @var LdapUserChecker
     */
    protected $userChecker;

    /**
     * @var string
     */
    protected $domain;

    /**
     * @var EventDispatcherInterface
     */
    protected $dispatcher;

    /**
     * @var AuthenticationSuccessHandlerInterface
     */
    protected $successHandler;

    /**
     * @var AuthenticationFailureHandlerInterface
     */
    protected $failureHandler;

    /**
     * @var AuthenticationEntryPointInterface
     */
    protected $entryPoint;

    /**
     * @var array
     */
    protected $options = [
        'hide_user_not_found_exceptions' => true,
        'username_parameter' => '_username',
        'password_parameter' => '_password',
        'domain_parameter' => '_ldap_domain',
        'post_only' => false,
        'remember_me' => false,
        'login_query_attribute' => null,
        'http_basic' => false,
        'http_basic_realm' => null,
        'http_basic_domain' => null,
    ];

    /**
     * @param bool $hideUserNotFoundExceptions
     * @param LdapUserChecker $userChecker
     * @param LdapManager $ldap
     * @param AuthenticationEntryPointInterface $entryPoint
     * @param EventDispatcherInterface $dispatcher
     * @param AuthenticationSuccessHandlerInterface $successHandler
     * @param AuthenticationFailureHandlerInterface $failureHandler
     * @param array $options
     * @param LdapUserProvider $ldapUserProvider
     */
    public function __construct($hideUserNotFoundExceptions = true, LdapUserChecker $userChecker, LdapManager $ldap, AuthenticationEntryPointInterface $entryPoint, EventDispatcherInterface $dispatcher, AuthenticationSuccessHandlerInterface $successHandler, AuthenticationFailureHandlerInterface $failureHandler, array $options, LdapUserProvider $ldapUserProvider)
    {
        $this->userChecker = $userChecker;
        $this->ldap = $ldap;
        $this->entryPoint = $entryPoint;
        $this->dispatcher = $dispatcher;
        $this->successHandler = $successHandler;
        $this->failureHandler = $failureHandler;
        $this->options['hide_user_not_found_exceptions'] = $hideUserNotFoundExceptions;
        $this->ldapUserProvider = $ldapUserProvider;
        $this->options = array_merge($this->options, $options);
    }

    /**
     * Allows to more easily extend the base LDAP guard service and set specific options.
     *
     * @param array $options
     * @return $this
     */
    public function setOptions(array $options)
    {
        $this->options = array_merge($this->options, $options);

        return $this;
    }

    /**
     * {@inheritdoc}
     */
    public function supports(Request $request)
    {
        return !empty($this->getRequestUsername($request));
    }

    /**
     * {@inheritdoc}
     */
    public function getCredentials(Request $request)
    {
        if (!$this->supports($request)) {
            return null;
        }
        $credentials = [
            'username' => $this->getRequestUsername($request),
            'password' => $this->getRequestPassword($request),
            'ldap_domain' => $this->getRequestDomain($request),
        ];
        $request->getSession()->set(Security::LAST_USERNAME, $credentials['username']);

        return $credentials;
    }

    /**
     * {@inheritdoc}
     */
    public function getUser($credentials, UserProviderInterface $userProvider)
    {
        $domain = $this->ldap->getDomainContext();

        try {
            $credDomain = isset($credentials['ldap_domain']) ? $credentials['ldap_domain'] : '';
            $this->switchDomainIfNeeded($credDomain);
            $this->setLdapCredentialsIfNeeded($credentials['username'], $credentials['password'], $userProvider);
            $user = $userProvider->loadUserByUsername($credentials['username']);
            $this->userChecker->checkPreAuth($user);

            return $user;
        } catch (UsernameNotFoundException $e) {
            $this->hideOrThrow($e, $this->options['hide_user_not_found_exceptions']);
        } catch (BadCredentialsException $e) {
            $this->hideOrThrow($e, $this->options['hide_user_not_found_exceptions']);
        } catch (LdapConnectionException $e) {
            $this->hideOrThrow($e, $this->options['hide_user_not_found_exceptions']);
        } catch (\Exception $e) {
            $this->hideOrThrow($e, $this->options['hide_user_not_found_exceptions']);
        } finally {
            $this->switchDomainBackIfNeeded($domain);
        }
    }

    /**
     * {@inheritdoc}
     */
    public function checkCredentials($credentials, UserInterface $user)
    {
        $domain = $this->ldap->getDomainContext();

        try {
            $credDomain = isset($credentials['ldap_domain']) ? $credentials['ldap_domain'] : '';
            $this->switchDomainIfNeeded($credDomain);
            /** @var \LdapTools\Operation\AuthenticationResponse $response */
            $response = $this->ldap->getConnection()->execute(
                new AuthenticationOperation(
                    $this->getBindUsername($user, $this->options['login_query_attribute']),
                    $credentials['password']
                )
            );
            if (!$response->isAuthenticated()) {
                $this->userChecker->checkLdapErrorCode(
                    $user,
                    $response->getErrorCode(),
                    $this->ldap->getConnection()->getConfig()->getLdapType()
                );
                throw new CustomUserMessageAuthenticationException(
                    $response->getErrorMessage(), [], $response->getErrorCode()
                );
            }
            // No way to get the token from the Guard, need to create one to pass...
            $token = new UsernamePasswordToken($user, $credentials['password'], 'ldap-tools', $user->getRoles());
            $token->setAttribute('ldap_domain', $credDomain);
            $this->dispatcher->dispatch(
                new LdapLoginEvent($user, $token),
                LdapLoginEvent::SUCCESS
            );
        } catch (\Exception $e) {
            $this->hideOrThrow($e, $this->options['hide_user_not_found_exceptions']);
        } finally {
            $this->domain = $this->ldap->getDomainContext();
            $this->switchDomainBackIfNeeded($domain);
        }

        return true;
    }

    /**
     * {@inheritdoc}
     */
    public function onAuthenticationSuccess(Request $request, TokenInterface $token, $providerKey)
    {
        $event = new AuthenticationHandlerEvent(
            $this->successHandler->onAuthenticationSuccess($request, $token),
            $request,
            null,
            $token,
            $providerKey
        );
        $this->dispatcher->dispatch($event, AuthenticationHandlerEvent::SUCCESS);

        return $this->options['http_basic'] ? null : $event->getResponse();
    }

    /**
     * {@inheritdoc}
     */
    public function onAuthenticationFailure(Request $request, AuthenticationException $exception)
    {
        $event = new AuthenticationHandlerEvent(
            $this->failureHandler->onAuthenticationFailure($request, $exception),
            $request,
            $exception
        );
        $this->dispatcher->dispatch($event, AuthenticationHandlerEvent::FAILURE);

        return $this->options['http_basic'] ? null : $event->getResponse();
    }

    /**
     * {@inheritdoc}
     */
    public function start(Request $request, AuthenticationException $authException = null)
    {
        $entryPoint = $this->options['http_basic'] ? new BasicAuthenticationEntryPoint($this->getHttpBasicRealm()) : $this->entryPoint;
        $event = new AuthenticationHandlerEvent(
            $entryPoint->start($request, $authException),
            $request,
            $authException
        );
        $this->dispatcher->dispatch($event, AuthenticationHandlerEvent::START);

        return $event->getResponse();
    }

    /**
     * {@inheritdoc}
     */
    public function supportsRememberMe()
    {
        return $this->options['remember_me'];
    }

    /**
     * {@inheritdoc}
     */
    public function createAuthenticatedToken(UserInterface $user, $providerKey)
    {
        $token = parent::createAuthenticatedToken($user, $providerKey);
        $token->setAttribute('ldap_domain', $this->domain);

        return $token;
    }

    /**
     * @param Request $request
     * @return null|string
     */
    protected function getRequestUsername(Request $request)
    {
        if ($this->options['http_basic']) {
            return $request->server->get('PHP_AUTH_USER');
        } else{
            return $this->getRequestParameter($this->options['username_parameter'], $request);
        }
    }

    /**
     * @param Request $request
     * @return null|string
     */
    protected function getRequestPassword(Request $request)
    {
        if ($this->options['http_basic']) {
            return $request->server->get('PHP_AUTH_PW');
        } else{
            return $this->getRequestParameter($this->options['password_parameter'], $request);
        }
    }

    /**
     * @param Request $request
     * @return null|string
     */
    protected function getRequestDomain(Request $request)
    {
        if ($this->options['http_basic']) {
            return $this->options['http_basic_domain'];
        } else{
            return $this->getRequestParameter($this->options['domain_parameter'], $request);
        }
    }

    /**
     * @param string $param
     * @param Request $request
     * @return string|null
     */
    protected function getRequestParameter($param, Request $request)
    {
        if ($this->options['post_only']) {
            $value = $request->request->get($param);
        } else {
            $value = $request->request->get($param) ?: $request->get($param);
        }

        return $value;
    }

    /**
     * @return string
     */
    protected function getHttpBasicRealm()
    {
        if ($this->options['http_basic_realm'] !== null) {
            $realm = $this->options['http_basic_realm'];
        } elseif ($this->options['http_basic_domain'] !== null) {
            $realm = $this->options['http_basic_domain'];
        } else {
            $realm = $this->ldap->getDomainContext();
        }

        return $realm;
    }
}
