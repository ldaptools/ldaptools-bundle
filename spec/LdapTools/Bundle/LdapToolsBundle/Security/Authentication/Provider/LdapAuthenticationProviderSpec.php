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

use LdapTools\Bundle\LdapToolsBundle\Event\LoadUserEvent;
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
     * @var AuthenticationOperation
     */
    protected $operation;

    function let(UserProviderInterface $userProvider, LdapUserChecker $userChecker, LdapManager $ldap, TokenInterface $token, LdapUser $user, LdapConnectionInterface $connection, AuthenticationResponse $response, \Symfony\Component\EventDispatcher\EventDispatcherInterface $dispatcher)
    {
        $this->operation = (new AuthenticationOperation())->setUsername('foo')->setPassword('bar');

        $token->getUsername()->willReturn('foo');
        $token->getCredentials()->willReturn('bar');
        $token->hasAttribute('ldap_domain')->willReturn(false);
        $token->getAttributes()->willReturn([]);
        $token->getUser()->willReturn($user);

        $userProvider->loadUserByUsername('foo')->willReturn($user);

        $connection->getConfig()->willReturn(new DomainConfiguration('foo.bar'));
        $connection->execute($this->operation)->willReturn($response);

        $response->isAuthenticated()->willReturn(true);

        $ldap->getConnection()->willReturn($connection);
        $ldap->getDomainContext()->willReturn('foo.bar');

        $user->getUsername()->willReturn('foo');
        $user->getRoles()->willReturn(['ROLE_USER']);
        $user->isAccountNonLocked()->willReturn(true);
        $user->isEnabled()->willReturn(true);
        $user->isAccountNonExpired()->willReturn(true);
        $user->isCredentialsNonExpired()->willReturn(true);

        $this->beConstructedWith(
            'restricted',
            true,
            $userProvider,
            new LdapUserChecker(),
            $ldap,
            $dispatcher
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

    function it_should_authenticate_a_token($token)
    {
        $this->authenticate($token)->shouldReturnAnInstanceOf('\Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken');
    }

    function it_should_add_data_to_the_new_token_correctly($token, $user)
    {
        $this->authenticate($token)->getRoles()->shouldHaveCount(1);
        $this->authenticate($token)->getUser()->shouldBeEqualTo($user);
        $this->authenticate($token)->getAttributes()->shouldBeEqualTo([]);
        $this->authenticate($token)->getProviderKey()->shouldBeEqualTo('restricted');
    }

    function it_should_throw_a_bad_credentials_exception_on_an_invalid_password($response, $token)
    {
        $response->isAuthenticated()->willReturn(false);
        $response->getErrorCode()->willReturn(9000);
        $response->getErrorMessage()->willReturn('foo');

        $e = new BadCredentialsException('Bad credentials.');
        $this->shouldThrow($e)->duringAuthenticate($token);
    }

    function it_should_throw_a_bad_credentials_exception_on_an_invalid_password_with_the_exact_message_if_specified($userProvider, $ldap, $dispatcher, $response, $token)
    {
        $this->beConstructedWith(
            'restricted',
            false,
            $userProvider,
            new LdapUserChecker(),
            $ldap,
            $dispatcher
        );
        $response->isAuthenticated()->willReturn(false);
        $response->getErrorCode()->willReturn(9000);
        $response->getErrorMessage()->willReturn('foo');

        $e = new BadCredentialsException('foo', 9000);
        $this->shouldThrow($e)->duringAuthenticate($token);
    }

    function it_should_throw_an_account_locked_exception_if_the_user_checker_detects_it($token, $user)
    {
        $user->isAccountNonLocked()->willReturn(false);
        $this->shouldThrow('\Symfony\Component\Security\Core\Exception\LockedException')->duringAuthenticate($token);
    }

    function it_should_throw_an_account_disabled_exception_if_the_user_checker_detects_it($token, $user)
    {
        $user->isEnabled()->willReturn(false);
        $this->shouldThrow('\Symfony\Component\Security\Core\Exception\DisabledException')->duringAuthenticate($token);
    }

    function it_should_throw_an_account_expired_exception_if_the_user_checker_detects_it($token, $user)
    {
        $user->isAccountNonExpired()->willReturn(false);
        $this->shouldThrow('\Symfony\Component\Security\Core\Exception\AccountExpiredException')->duringAuthenticate($token);
    }

    function it_should_throw_a_bad_credentials_exception_by_default_if_the_user_is_not_found($token, $userProvider)
    {
        $userProvider->loadUserByUsername('foo')->willThrow(new UsernameNotFoundException());
        $this->shouldThrow('\Symfony\Component\Security\Core\Exception\BadCredentialsException')->duringAuthenticate($token);
    }

    function it_should_throw_a_username_not_found_exception_when_specified_if_a_user_is_not_found($userProvider, $ldap, $dispatcher, $token)
    {
        $this->beConstructedWith(
            'restricted',
            false,
            $userProvider,
            new LdapUserChecker(),
            $ldap,
            $dispatcher
        );
        $userProvider->loadUserByUsername('foo')->willThrow(new UsernameNotFoundException());

        $this->shouldThrow(new UsernameNotFoundException())->duringAuthenticate($token);
    }

    function it_should_throw_an_account_locked_exception_if_detected_by_the_auth_error_code($connection, $token)
    {
        $connection->execute($this->operation)->willReturn(new AuthenticationResponse(false,'foo', ADResponseCodes::ACCOUNT_LOCKED));
        $this->shouldThrow('\Symfony\Component\Security\Core\Exception\LockedException')->duringAuthenticate($token);
    }

    function it_should_throw_an_account_disabled_exception_if_detected_by_the_auth_error_code($connection, $token)
    {
        $connection->execute($this->operation)->willReturn(new AuthenticationResponse(false,'foo', ADResponseCodes::ACCOUNT_DISABLED));
        $this->shouldThrow('\Symfony\Component\Security\Core\Exception\DisabledException')->duringAuthenticate($token);
    }

    function it_should_throw_a_credentials_expired_exception_if_detected_by_the_auth_error_code($connection, $token)
    {
        $connection->execute($this->operation)->willReturn(new AuthenticationResponse(false,'foo', ADResponseCodes::ACCOUNT_PASSWORD_MUST_CHANGE));
        $this->shouldThrow('\Symfony\Component\Security\Core\Exception\CredentialsExpiredException')->duringAuthenticate($token);
    }

    function it_should_throw_a_bad_credentials_exception_if_a_connection_issue_occurs_during_authentication($connection, $token)
    {
        $connection->execute($this->operation)->willThrow(new LdapConnectionException('fail'));
        $this->shouldThrow('\Symfony\Component\Security\Core\Exception\BadCredentialsException')->duringAuthenticate($token);
    }

    function it_should_switch_the_domain_if_the_token_has_the_ldap_domain_set($ldap, $token)
    {
        // It first grabs a copy of the domain context, then checks against it, then checks it at the end...
        $ldap->getDomainContext()->willReturn('foo.bar', 'foo.bar', 'example.local');

        $token->hasAttribute('ldap_domain')->willReturn(true);
        $token->getAttribute('ldap_domain')->willReturn('example.local');

        $ldap->switchDomain('example.local')->shouldBeCalledTimes(1);
        $ldap->switchDomain('foo.bar')->shouldBeCalledTimes(1);

        $this->authenticate($token)->shouldReturnAnInstanceOf('\Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken');
    }
    
    function it_should_call_a_login_success_event($token, $dispatcher)
    {
        $dispatcher->dispatch('ldap_tools_bundle.login.success', Argument::type('LdapTools\Bundle\LdapToolsBundle\Event\LdapLoginEvent'))->shouldBeCalled();
        $this->authenticate($token);
    }
}
