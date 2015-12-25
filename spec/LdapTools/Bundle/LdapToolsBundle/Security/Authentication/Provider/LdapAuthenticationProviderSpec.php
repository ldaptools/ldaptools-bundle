<?php
/**
 * This file is part of the LdapToolsBundle package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace spec\LdapTools\Bundle\LdapToolsBundle\Security\Authentication\Provider;

use LdapTools\Bundle\LdapToolsBundle\Security\User\LdapUser;
use LdapTools\Bundle\LdapToolsBundle\Security\User\LdapUserChecker;
use LdapTools\Connection\ADResponseCodes;
use LdapTools\Connection\LdapConnectionInterface;
use LdapTools\DomainConfiguration;
use LdapTools\Exception\LdapConnectionException;
use LdapTools\LdapManager;
use LdapTools\Operation\AuthenticationOperation;
use LdapTools\Operation\AuthenticationResponse;
use PhpSpec\ObjectBehavior;
use Prophecy\Argument;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;
use Symfony\Component\Security\Core\Exception\UsernameNotFoundException;
use Symfony\Component\Security\Core\User\UserProviderInterface;

class LdapAuthenticationProviderSpec extends ObjectBehavior
{
    /**
     * @var LdapUserChecker
     */
    protected $userChecker;

    /**
     * @var UserProviderInterface
     */
    protected $userProvider;

    /**
     * @var LdapManager
     */
    protected $ldap;

    /**
     * @var TokenInterface
     */
    protected $token;

    /**
     * @var LdapUser
     */
    protected $user;

    /**
     * @var LdapConnectionInterface
     */
    protected $connection;

    /**
     * @var DomainConfiguration
     */
    protected $config;

    /**
     * @var AuthenticationOperation
     */
    protected $operation;

    /**
     * @var AuthenticationResponse
     */
    protected $response;

    /**
     * @param \Symfony\Component\Security\Core\User\UserProviderInterface $userProvider
     * @param \LdapTools\Bundle\LdapToolsBundle\Security\User\LdapUserChecker $userChecker
     * @param \LdapTools\LdapManager $ldap
     * @param \Symfony\Component\Security\Core\Authentication\Token\TokenInterface $token
     * @param \LdapTools\Bundle\LdapToolsBundle\Security\User\LdapUser $user
     * @param \LdapTools\Connection\LdapConnectionInterface $connection
     * @param \LdapTools\Operation\AuthenticationResponse $response
     */
    function let($userProvider, $userChecker, $ldap, $token, $user, $connection, $response)
    {
        $this->userProvider = $userProvider;
        $this->userChecker = $userChecker;
        $this->ldap = $ldap;
        $this->token = $token;
        $this->user = $user;
        $this->connection = $connection;
        $this->operation = (new AuthenticationOperation())->setUsername('foo')->setPassword('bar');
        $this->response = $response;

        $token->getUsername()->willReturn('foo');
        $token->getCredentials()->willReturn('bar');
        $token->hasAttribute('ldap_domain')->willReturn(false);
        $token->getAttributes()->willReturn([]);

        $this->userProvider->loadUserByUsername('foo')->willReturn($user);

        $this->connection->getConfig()->willReturn(new DomainConfiguration('foo.bar'));
        $this->connection->execute($this->operation)->willReturn($this->response);

        $this->response->isAuthenticated()->willReturn(true);

        $this->ldap->getConnection()->willReturn($this->connection);
        $this->ldap->getDomainContext()->willReturn('foo.bar');

        $this->user->getUsername()->willReturn('foo');
        $this->user->getRoles()->willReturn(['ROLE_USER']);
        $this->user->isAccountNonLocked()->willReturn(true);
        $this->user->isEnabled()->willReturn(true);
        $this->user->isAccountNonExpired()->willReturn(true);
        $this->user->isCredentialsNonExpired()->willReturn(true);

        $this->beConstructedWith(
            'restricted',
            true,
            $this->userProvider,
            new LdapUserChecker(),
            $this->ldap
        );
    }

    function it_is_initializable()
    {
        $this->shouldHaveType('LdapTools\Bundle\LdapToolsBundle\Security\Authentication\Provider\LdapAuthenticationProvider');
    }

    function it_should_support_a_username_password_token()
    {
        $this->supports(new UsernamePasswordToken('foo', 'bar', 'foo'))->shouldBeEqualTo(true);
    }

    function it_should_authenticate_a_token()
    {
        $this->authenticate($this->token)->shouldReturnAnInstanceOf('\Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken');
    }

    function it_should_add_data_to_the_new_token_correctly()
    {
        $this->authenticate($this->token)->getRoles()->shouldHaveCount(1);
        $this->authenticate($this->token)->getUser()->shouldBeEqualTo($this->user);
        $this->authenticate($this->token)->getAttributes()->shouldBeEqualTo([]);
        $this->authenticate($this->token)->getProviderKey()->shouldBeEqualTo('restricted');
    }

    function it_should_throw_a_bad_credentials_exception_on_an_invalid_password()
    {
        $this->response->isAuthenticated()->willReturn(false);
        $this->response->getErrorCode()->willReturn(9000);
        $this->response->getErrorMessage()->willReturn('foo');

        $e = new BadCredentialsException('Bad credentials.');
        $this->shouldThrow($e)->duringAuthenticate($this->token);
    }

    function it_should_throw_a_bad_credentials_exception_on_an_invalid_password_with_the_exact_message_if_specified()
    {
        $this->beConstructedWith(
            'restricted',
            false,
            $this->userProvider,
            new LdapUserChecker(),
            $this->ldap
        );
        $this->response->isAuthenticated()->willReturn(false);
        $this->response->getErrorCode()->willReturn(9000);
        $this->response->getErrorMessage()->willReturn('foo');

        $e = new BadCredentialsException('foo', 9000);
        $this->shouldThrow($e)->duringAuthenticate($this->token);
    }

    function it_should_throw_an_account_locked_exception_if_the_user_checker_detects_it()
    {
        $this->user->isAccountNonLocked()->willReturn(false);
        $this->shouldThrow('\Symfony\Component\Security\Core\Exception\LockedException')->duringAuthenticate($this->token);
    }

    function it_should_throw_an_account_disabled_exception_if_the_user_checker_detects_it()
    {
        $this->user->isEnabled()->willReturn(false);
        $this->shouldThrow('\Symfony\Component\Security\Core\Exception\DisabledException')->duringAuthenticate($this->token);
    }

    function it_should_throw_an_account_expired_exception_if_the_user_checker_detects_it()
    {
        $this->user->isAccountNonExpired()->willReturn(false);
        $this->shouldThrow('\Symfony\Component\Security\Core\Exception\AccountExpiredException')->duringAuthenticate($this->token);
    }

    function it_should_throw_a_bad_credentials_exception_by_default_if_the_user_is_not_found()
    {
        $this->userProvider->loadUserByUsername('foo')->willThrow(new UsernameNotFoundException());
        $this->shouldThrow('\Symfony\Component\Security\Core\Exception\BadCredentialsException')->duringAuthenticate($this->token);
    }

    function it_should_throw_a_username_not_found_exception_when_specified_if_a_user_is_not_found()
    {
        $this->beConstructedWith(
            'restricted',
            false,
            $this->userProvider,
            new LdapUserChecker(),
            $this->ldap
        );
        $this->userProvider->loadUserByUsername('foo')->willThrow(new UsernameNotFoundException());

        $this->shouldThrow(new UsernameNotFoundException())->duringAuthenticate($this->token);
    }

    function it_should_throw_an_account_locked_exception_if_detected_by_the_auth_error_code()
    {
        $this->connection->execute($this->operation)->willReturn(new AuthenticationResponse(false,'foo', ADResponseCodes::ACCOUNT_LOCKED));
        $this->shouldThrow('\Symfony\Component\Security\Core\Exception\LockedException')->duringAuthenticate($this->token);
    }

    function it_should_throw_an_account_disabled_exception_if_detected_by_the_auth_error_code()
    {
        $this->connection->execute($this->operation)->willReturn(new AuthenticationResponse(false,'foo', ADResponseCodes::ACCOUNT_DISABLED));
        $this->shouldThrow('\Symfony\Component\Security\Core\Exception\DisabledException')->duringAuthenticate($this->token);
    }

    function it_should_throw_a_credentials_expired_exception_if_detected_by_the_auth_error_code()
    {
        $this->connection->execute($this->operation)->willReturn(new AuthenticationResponse(false,'foo', ADResponseCodes::ACCOUNT_PASSWORD_MUST_CHANGE));
        $this->shouldThrow('\Symfony\Component\Security\Core\Exception\CredentialsExpiredException')->duringAuthenticate($this->token);
    }

    function it_should_throw_a_bad_credentials_exception_if_a_connection_issue_occurs_during_authentication()
    {
        $this->connection->execute($this->operation)->willThrow(new LdapConnectionException('fail'));
        $this->shouldThrow('\Symfony\Component\Security\Core\Exception\BadCredentialsException')->duringAuthenticate($this->token);
    }

    function it_should_switch_the_domain_if_the_token_has_the_ldap_domain_set()
    {
        // It first grabs a copy of the domain context, then checks against it, then checks it at the end...
        $this->ldap->getDomainContext()->willReturn('foo.bar', 'foo.bar', 'example.local');

        $this->token->hasAttribute('ldap_domain')->willReturn(true);
        $this->token->getAttribute('ldap_domain')->willReturn('example.local');

        $this->ldap->switchDomain('example.local')->shouldBeCalledTimes(1);
        $this->ldap->switchDomain('foo.bar')->shouldBeCalledTimes(1);

        $this->authenticate($this->token)->shouldReturnAnInstanceOf('\Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken');
    }
}
