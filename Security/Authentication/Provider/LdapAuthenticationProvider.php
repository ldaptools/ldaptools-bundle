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
use LdapTools\Bundle\LdapToolsBundle\Security\LdapAuthenticationTrait;
use LdapTools\Bundle\LdapToolsBundle\Security\User\LdapUserChecker;
use LdapTools\Bundle\LdapToolsBundle\Security\User\LdapUserProvider;
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
    use LdapAuthenticationTrait;

    /**
     * @var UserProviderInterface
     */
    protected $userProvider;

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
     * @var array
     */
    protected $options = [
        'login_query_attribute' => null,
    ];

    /**
     * @param string $providerKey
     * @param bool $hideUserNotFoundExceptions
     * @param UserProviderInterface $userProvider
     * @param LdapUserChecker $userChecker
     * @param LdapManager $ldap
     * @param EventDispatcherInterface $dispatcher
     * @param LdapUserProvider $ldapUserProvider
     * @param array $options
     */
    public function __construct(
        $providerKey,
        $hideUserNotFoundExceptions = true,
        UserProviderInterface $userProvider,
        LdapUserChecker $userChecker,
        LdapManager $ldap,
        EventDispatcherInterface $dispatcher,
        LdapUserProvider $ldapUserProvider,
        array $options
    ) {
        $this->userProvider = $userProvider;
        $this->ldap = $ldap;
        $this->hideUserNotFoundExceptions = $hideUserNotFoundExceptions;
        $this->providerKey = $providerKey;
        $this->userChecker = $userChecker;
        $this->dispatcher = $dispatcher;
        $this->ldapUserProvider = $ldapUserProvider;
        $this->options = array_merge($this->options, $options);
    }

    /**
     * {@inheritdoc}
     */
    public function authenticate(TokenInterface $token)
    {
        $domain = $this->ldap->getDomainContext();

        try {
            $this->switchDomainIfNeeded($this->getDomainFromToken($token));
            $this->setLdapCredentialsIfNeeded($token->getUsername(), $token->getCredentials(), $this->userProvider);
            $user = $this->userProvider->loadUserByUsername($token->getUsername());
            $this->userChecker->checkPreAuth($user);
            $token = $this->doAuthentication($user, $token);
            $this->userChecker->checkPostAuth($user);
        } catch (UsernameNotFoundException $e) {
            $this->hideOrThrow($e, $this->hideUserNotFoundExceptions);
        } catch (BadCredentialsException $e) {
            $this->hideOrThrow($e, $this->hideUserNotFoundExceptions);
        } catch (LdapConnectionException $e) {
            $this->hideOrThrow($e, $this->hideUserNotFoundExceptions);
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
        $auth = new AuthenticationOperation(
            $this->getBindUsername($user, $this->options['login_query_attribute']),
            $token->getCredentials()
        );
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
        $this->dispatcher->dispatch(LdapLoginEvent::SUCCESS, new LdapLoginEvent($user, $token));

        $newToken = new UsernamePasswordToken($user, null, $this->providerKey, $user->getRoles());
        $newToken->setAttributes($token->getAttributes());

        return $newToken;
    }

    /**
     * @param TokenInterface $token
     * @return string
     */
    protected function getDomainFromToken(TokenInterface $token)
    {
        return $token->hasAttribute('ldap_domain') ? $token->getAttribute('ldap_domain') : '';
    }
}
