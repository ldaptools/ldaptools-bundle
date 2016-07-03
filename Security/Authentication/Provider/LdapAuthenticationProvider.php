<?php
/**
 * This file is part of the LdapToolsBundle package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace LdapTools\Bundle\LdapToolsBundle\Security\Authentication\Provider;

use LdapTools\Bundle\LdapToolsBundle\Event\LdapLoginEvent;
use LdapTools\Bundle\LdapToolsBundle\Security\User\LdapUserChecker;
use LdapTools\Exception\LdapConnectionException;
use LdapTools\LdapManager;
use LdapTools\Operation\AuthenticationOperation;
use LdapTools\Operation\AuthenticationResponse;
use Symfony\Component\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\Security\Core\Authentication\Provider\AuthenticationProviderInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;
use Symfony\Component\Security\Core\Exception\UsernameNotFoundException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;

/**
 * Authenticate a user against LDAP.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class LdapAuthenticationProvider implements AuthenticationProviderInterface
{
    /**
     * @var UserProviderInterface
     */
    protected $userProvider;

    /**
     * @var LdapManager
     */
    protected $ldap;

    /**
     * @var bool
     */
    protected $hideUserNotFoundExceptions;

    /**
     * @var string
     */
    protected $providerKey;

    /**
     * @var LdapUserChecker
     */
    protected $userChecker;

    /**
     * @var EventDispatcherInterface
     */
    protected $dispatcher;

    /**
     * @param string $providerKey
     * @param bool $hideUserNotFoundExceptions
     * @param UserProviderInterface $userProvider
     * @param LdapUserChecker $userChecker
     * @param LdapManager $ldap
     */
    public function __construct(
        $providerKey,
        $hideUserNotFoundExceptions = true,
        UserProviderInterface $userProvider,
        LdapUserChecker $userChecker,
        LdapManager $ldap,
        EventDispatcherInterface $dispatcher
    ) {
        $this->userProvider = $userProvider;
        $this->ldap = $ldap;
        $this->hideUserNotFoundExceptions = $hideUserNotFoundExceptions;
        $this->providerKey = $providerKey;
        $this->userChecker = $userChecker;
        $this->dispatcher = $dispatcher;
    }

    /**
     * {@inheritdoc}
     */
    public function authenticate(TokenInterface $token)
    {
        $domain = $this->ldap->getDomainContext();
        $this->switchDomainIfNeeded($token);

        try {
            $user = $this->userProvider->loadUserByUsername($token->getUsername());
            $this->userChecker->checkPreAuth($user);
            $token = $this->doAuthentication($user, $token);
            $this->userChecker->checkPostAuth($user);
        } catch (UsernameNotFoundException $e) {
            $this->hideOrThrow($e);
        } catch (BadCredentialsException $e) {
            $this->hideOrThrow($e);
        } catch (LdapConnectionException $e) {
            $this->hideOrThrow($e);
        } finally {
            $this->switchDomainBackIfNeeded($domain);
        }

        return $token;
    }

    /**
     * {@inheritdoc}
     */
    public function supports(TokenInterface $token)
    {
        return ($token instanceof UsernamePasswordToken);
    }

    /**
     * @param UserInterface $user
     * @param TokenInterface $token
     * @return UsernamePasswordToken
     */
    protected function doAuthentication(UserInterface $user, TokenInterface $token)
    {
        $auth = (new AuthenticationOperation())->setUsername($user->getUsername())->setPassword($token->getCredentials());
        /** @var AuthenticationResponse $response */
        $response = $this->ldap->getConnection()->execute($auth);

        if (!$response->isAuthenticated()) {
            $this->userChecker->checkLdapErrorCode(
                $user,
                $response->getErrorCode(),
                $this->ldap->getConnection()->getConfig()->getLdapType()
            );

            throw new BadCredentialsException($response->getErrorMessage(), $response->getErrorCode());
        }
        $this->dispatcher->dispatch(LdapLoginEvent::SUCCESS, new LdapLoginEvent($user));

        $newToken = new UsernamePasswordToken($user, null, $this->providerKey, $user->getRoles());
        $newToken->setAttributes($token->getAttributes());

        return $newToken;
    }

    /**
     * If the domain needs to a different context for the request, then switch it.
     *
     * @param TokenInterface $token
     */
    protected function switchDomainIfNeeded(TokenInterface $token)
    {
        if ($token->hasAttribute('ldap_domain') && $this->ldap->getDomainContext() !== $token->getAttribute('ldap_domain')) {
            $this->ldap->switchDomain($token->getAttribute('ldap_domain'));
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

        throw $e;
    }
}
