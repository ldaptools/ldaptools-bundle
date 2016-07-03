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

use LdapTools\Bundle\LdapToolsBundle\Event\LdapLoginEvent;
use LdapTools\Exception\Exception;
use LdapTools\Operation\AuthenticationOperation;
use Symfony\Component\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\RouterInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;
use Symfony\Component\Security\Core\Exception\CustomUserMessageAuthenticationException;
use Symfony\Component\Security\Core\Exception\UsernameNotFoundException;
use Symfony\Component\Security\Core\Security;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Guard\AbstractGuardAuthenticator;
use LdapTools\Bundle\LdapToolsBundle\Security\User\LdapUserChecker;
use LdapTools\Exception\LdapConnectionException;
use LdapTools\LdapManager;

/**
 * LDAP Guard Authenticator.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class LdapGuardAuthenticator extends AbstractGuardAuthenticator
{
    /**
     * @var LdapManager
     */
    protected $ldap;

    /**
     * @var bool
     */
    protected $hideUserNotFoundExceptions;

    /**
     * @var LdapUserChecker
     */
    protected $userChecker;

    /**
     * @var string
     */
    protected $domain;

    /**
     * @var RouterInterface
     */
    protected $router;

    /**
     * @var EventDispatcherInterface
     */
    protected $dispatcher;

    /**
     * @var string The entry point/start path route name.
     */
    protected $startPath = 'login';

    /**
     * @param bool $hideUserNotFoundExceptions
     * @param LdapUserChecker $userChecker
     * @param LdapManager $ldap
     * @param RouterInterface $router
     * @param EventDispatcherInterface $dispatcher
     */
    public function __construct($hideUserNotFoundExceptions = true, LdapUserChecker $userChecker, LdapManager $ldap, RouterInterface $router, EventDispatcherInterface $dispatcher)
    {
        $this->hideUserNotFoundExceptions = $hideUserNotFoundExceptions;
        $this->userChecker = $userChecker;
        $this->ldap = $ldap;
        $this->router = $router;
        $this->dispatcher = $dispatcher;
    }

    /**
     * {@inheritdoc}
     */
    public function getCredentials(Request $request)
    {
        $credentials = [
            'username' => '',
            'password' => '',
            'ldap_domain' => '',
        ];
        foreach (array_keys($credentials) as $key) {
            $param = "_$key";
            $value = $request->request->get($param) ?: $request->get($param);
            $credentials[$key] = $value;
        }

        if (empty($credentials['username'])) {
            return null;
        }
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
            $this->switchDomainIfNeeded($credentials);
            $user = $userProvider->loadUserByUsername($credentials['username']);
            $this->userChecker->checkPreAuth($user);

            return $user;
        } catch (UsernameNotFoundException $e) {
            $this->hideOrThrow($e);
        } catch (BadCredentialsException $e) {
            $this->hideOrThrow($e);
        } catch (LdapConnectionException $e) {
            $this->hideOrThrow($e);
        } catch (\Exception $e) {
            $this->hideOrThrow($e);
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
            $this->switchDomainIfNeeded($credentials);
            /** @var \LdapTools\Operation\AuthenticationResponse $response */
            $response = $this->ldap->getConnection()->execute(
                new AuthenticationOperation($user->getUsername(), $credentials['password'])
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
            $this->dispatcher->dispatch(LdapLoginEvent::SUCCESS, new LdapLoginEvent($user));
        } catch (\Exception $e) {
            $this->hideOrThrow($e);
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
        if ($request->getSession()->has('_security.main.target_path')) {
            $url = $request->getSession()->get('_security.main.target_path');
        } else {
            $url = '/';
        }

        return new RedirectResponse($url);
    }

    /**
     * {@inheritdoc}
     */
    public function onAuthenticationFailure(Request $request, AuthenticationException $exception)
    {
        $request->getSession()->set(Security::AUTHENTICATION_ERROR, $exception);

        return new RedirectResponse($this->router->generate($this->startPath));
    }

    /**
     * {@inheritdoc}
     */
    public function start(Request $request, AuthenticationException $authException = null)
    {
        return new RedirectResponse($this->router->generate($this->startPath));
    }

    /**
     * {@inheritdoc}
     */
    public function supportsRememberMe()
    {
        return false;
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
     * Set the entry point/start path.
     *
     * @param string $startPath
     */
    public function setStartPath($startPath)
    {
        $this->startPath = $startPath;
    }

    /**
     * If the domain needs to a different context for the request, then switch it.
     *
     * @param array $credentials
     */
    protected function switchDomainIfNeeded($credentials)
    {
        if (!empty($credentials['ldap_domain']) && $this->ldap->getDomainContext() !== $credentials['ldap_domain']) {
            $this->ldap->switchDomain($credentials['ldap_domain']);
        }
    }

    /**
     * If the passed domain is not the current context, then switch back to it.
     *
     * @param string $domain
     */
    protected function switchDomainBackIfNeeded($domain)
    {
        if ($domain !== $this->ldap->getDomainContext()) {
            $this->ldap->switchDomain($domain);
        }
    }

    /**
     * Determine whether or not the exception should be masked with a BadCredentials or not.
     *
     * @param \Exception $e
     * @throws \Exception
     */
    protected function hideOrThrow(\Exception $e)
    {
        if ($this->hideUserNotFoundExceptions) {
            throw new BadCredentialsException('Bad credentials.', 0, $e);
        }
        // Specifically show LdapTools related exceptions, ignore others. 
        if (!$this->hideUserNotFoundExceptions && $e instanceof Exception) {
            throw new CustomUserMessageAuthenticationException($e->getMessage(), [], $e->getCode());
        }

        throw $e;
    }
}
