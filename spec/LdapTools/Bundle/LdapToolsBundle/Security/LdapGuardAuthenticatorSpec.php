<?php
/**
 * This file is part of the LdapToolsBundle package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace spec\LdapTools\Bundle\LdapToolsBundle\Security;

use LdapTools\Bundle\LdapToolsBundle\Event\LdapLoginEvent;
use LdapTools\Bundle\LdapToolsBundle\Security\User\LdapUser;
use LdapTools\Bundle\LdapToolsBundle\Security\User\LdapUserChecker;
use LdapTools\Connection\ADResponseCodes;
use LdapTools\Connection\LdapConnectionInterface;
use LdapTools\DomainConfiguration;
use LdapTools\Exception\InvalidArgumentException;
use LdapTools\Exception\LdapConnectionException;
use LdapTools\LdapManager;
use LdapTools\Object\LdapObject;
use LdapTools\Operation\AuthenticationOperation;
use LdapTools\Operation\AuthenticationResponse;
use PhpSpec\ObjectBehavior;
use Prophecy\Argument;
use Symfony\Component\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Session\Session;
use Symfony\Component\Routing\RouterInterface;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;
use Symfony\Component\Security\Core\Exception\CustomUserMessageAuthenticationException;
use Symfony\Component\Security\Core\Exception\UsernameNotFoundException;

/**
 * @require Symfony\Component\Security\Guard\AbstractGuardAuthenticator
 */
class LdapGuardAuthenticatorSpec extends ObjectBehavior
{
    /**
     * @var LdapManager
     */
    protected $ldap;

    /**
     * @var LdapUserChecker
     */
    protected $userChecker;

    /**
     * @var Request
     */
    protected $request;

    /**
     * @var DomainConfiguration
     */
    protected $config;

    /**
     * @var LdapConnectionInterface
     */
    protected $connection;

    /**
     * @var RouterInterface
     */
    protected $router;

    /**
     * @var EventDispatcherInterface
     */
    protected $dispatcher;

    /**
     * @var array
     */
    protected $requestCreds = [
        '_username' => 'foo',
        '_password' => 'bar',
        '_ldap_domain' => 'foo.bar',
    ];

    /**
     * @var array
     */
    protected $credentials = [
        'username' => 'foo',
        'password' => 'bar',
        'ldap_domain' => 'foo.bar',
    ];
    
    /**
     * @param \LdapTools\LdapManager $ldap
     * @param \LdapTools\Connection\LdapConnectionInterface $connection
     * @param \Symfony\Component\Routing\RouterInterface $router
     * @param \Symfony\Component\EventDispatcher\EventDispatcherInterface $dispatcher
     */
    function let($ldap, $connection, $router, $dispatcher)
    {
        $this->ldap = $ldap;
        $this->router = $router;
        $this->userChecker = new LdapUserChecker();
        $this->connection = $connection;
        $this->config = new DomainConfiguration('foo.bar');
        $this->request = new Request();
        $this->request->setSession(new Session());
        $this->dispatcher = $dispatcher;

        $this->router->generate('login')->willReturn('/login');
        $this->connection->getConfig()->willReturn($this->config);
        $this->ldap->getConnection()->willReturn($this->connection);
        $this->ldap->getDomainContext()->willReturn('foo.bar');

        $this->beConstructedWith(true, $this->userChecker, $ldap, $router, $dispatcher);
    }

    function it_is_initializable()
    {
        $this->shouldHaveType('LdapTools\Bundle\LdapToolsBundle\Security\LdapGuardAuthenticator');
    }
    
    function it_should_get_the_credentials_array()
    {
        $this->request->request->add($this->requestCreds);
        
        $this->getCredentials($this->request)->shouldBeEqualTo(['username' => 'foo', 'password' => 'bar', 'ldap_domain' => 'foo.bar']);
    }
    
    function it_should_get_null_when_getting_the_credentials_array_with_no_username_set()
    {
        $this->getCredentials($this->request)->shouldBeNull();
    }

    /**
     * @param \Symfony\Component\Security\Core\User\UserProviderInterface $up
     */
    function it_should_get_a_user_object($up)
    {
        $credentials = $this->credentials;
        $credentials['ldap_domain'] = '';
        $user = new LdapUser(New LdapObject(['username' => 'foo']));

        $this->ldap->switchDomain(Argument::any())->shouldNotBeCalled();
        $up->loadUserByUsername('foo')->shouldBeCalled()->willReturn($user);

        $this->getUser($this->credentials, $up)->shouldBeEqualTo($user);
    }

    /**
     * @param \Symfony\Component\Security\Core\User\UserProviderInterface $up
     */
    function it_should_throw_an_exception_when_a_username_isnt_found($up)
    {
        $credentials = $this->credentials;
        $credentials['ldap_domain'] = '';
        
        $up->loadUserByUsername('foo')->shouldBeCalled()->willThrow(new UsernameNotFoundException('foo'));
        $this->shouldThrow('Symfony\Component\Security\Core\Exception\BadCredentialsException')->duringGetUser($this->credentials, $up);

        $up->loadUserByUsername('foo')->shouldBeCalled()->willThrow(new LdapConnectionException('unavailable'));
        $this->shouldThrow('Symfony\Component\Security\Core\Exception\BadCredentialsException')->duringGetUser($this->credentials, $up);

        $up->loadUserByUsername('foo')->shouldBeCalled()->willThrow(new BadCredentialsException('bad'));
        $this->shouldThrow('Symfony\Component\Security\Core\Exception\BadCredentialsException')->duringGetUser($this->credentials, $up);
    }

    /**
     * @param \Symfony\Component\Security\Core\User\UserProviderInterface $up
     */
    function it_should_not_hide_the_exception_message_when_specified($up)
    {
        $credentials = $this->credentials;
        $credentials['ldap_domain'] = '';
        $this->beConstructedWith(false, $this->userChecker, $this->ldap, $this->router, $this->dispatcher);

        $e = new CustomUserMessageAuthenticationException('unavailable');
        $up->loadUserByUsername('foo')->shouldBeCalled()->willThrow(new LdapConnectionException('unavailable'));
        $this->shouldThrow($e)->duringGetUser($this->credentials, $up);
        
        $e = new UsernameNotFoundException('foo');
        $up->loadUserByUsername('foo')->shouldBeCalled()->willThrow($e);
        $this->shouldThrow($e)->duringGetUser($this->credentials, $up);

        $e = new BadCredentialsException('bar');
        $up->loadUserByUsername('foo')->shouldBeCalled()->willThrow($e);
        $this->shouldThrow($e)->duringGetUser($this->credentials, $up);
    }

    /**
     * @param \Symfony\Component\Security\Core\User\UserProviderInterface $up
     */
    function it_should_throw_an_exception_when_a_user_is_loaded_that_is_disabled_or_locked($up)
    {
        $credentials = $this->credentials;
        $credentials['ldap_domain'] = '';
        $this->beConstructedWith(false, $this->userChecker, $this->ldap, $this->router, $this->dispatcher);
        
        $user = new LdapUser(new LdapObject([
            'username' => 'foo',
            'disabled' => true,
        ]));
        $up->loadUserByUsername('foo')->shouldBeCalled()->willReturn($user);
        $this->shouldThrow('Symfony\Component\Security\Core\Exception\DisabledException')->duringGetUser($this->credentials, $up);

        $user = new LdapUser(new LdapObject([
            'username' => 'foo',
            'locked' => true,
        ]));
        $up->loadUserByUsername('foo')->shouldBeCalled()->willReturn($user);
        $this->shouldThrow('Symfony\Component\Security\Core\Exception\LockedException')->duringGetUser($this->credentials, $up);
    }

    /**
     * @param \Symfony\Component\Security\Core\User\UserProviderInterface $up
     */
    function it_should_switch_the_domain_name_when_loading_a_user_if_the_domain_parameter_is_set($up)
    {
        $credentials = $this->credentials;
        $credentials['ldap_domain'] = 'foo.local';
        $user = new LdapUser(New LdapObject(['username' => 'foo']));

        $this->ldap->switchDomain('foo.local')->shouldBeCalled()->willReturn($this->connection);
        $up->loadUserByUsername('foo')->shouldBeCalled()->willReturn($user);

        $this->getUser($credentials, $up)->shouldBeEqualTo($user);
    }

    function it_should_check_the_credentials_of_a_loaded_user()
    {
        $credentials = $this->credentials;
        $credentials['ldap_domain'] = '';
        $user = new LdapUser(New LdapObject(['username' => 'foo']));

        $this->connection->execute(new AuthenticationOperation('foo', 'bar'))->shouldBeCalled()->willReturn(new AuthenticationResponse(true));
        $this->checkCredentials($credentials, $user)->shouldReturn(true);
    }

    function it_should_throw_an_exception_if_checking_credentials_fails()
    {
        $credentials = $this->credentials;
        $credentials['ldap_domain'] = '';
        $user = new LdapUser(New LdapObject(['username' => 'foo']));

        $this->connection->execute(new AuthenticationOperation('foo', 'bar'))->shouldBeCalled()->willReturn(new AuthenticationResponse(false, 'foo', 1));
        $this->shouldThrow('Symfony\Component\Security\Core\Exception\BadCredentialsException')->duringCheckCredentials($credentials, $user);

        $this->connection->execute(new AuthenticationOperation('foo', 'bar'))->shouldBeCalled()->willReturn(new AuthenticationResponse(false, 'foo', ADResponseCodes::ACCOUNT_DISABLED));
        $this->shouldThrow('Symfony\Component\Security\Core\Exception\BadCredentialsException')->duringCheckCredentials($credentials, $user);
    }
    
    function it_should_not_mask_the_error_message_when_checking_credentials_if_specified()
    {
        $credentials = $this->credentials;
        $credentials['ldap_domain'] = '';
        $this->beConstructedWith(false, $this->userChecker, $this->ldap, $this->router, $this->dispatcher);
        $user = new LdapUser(New LdapObject(['username' => 'foo']));
        
        $this->connection->execute(new AuthenticationOperation('foo', 'bar'))->shouldBeCalled()->willReturn(
            new AuthenticationResponse(false, ADResponseCodes::RESPONSE_MESSAGE[ADResponseCodes::ACCOUNT_PASSWORD_MUST_CHANGE], ADResponseCodes::ACCOUNT_PASSWORD_MUST_CHANGE)
        );
        $this->shouldThrow('Symfony\Component\Security\Core\Exception\CredentialsExpiredException')->duringCheckCredentials($this->credentials, $user);

        $this->connection->execute(new AuthenticationOperation('foo', 'bar'))->shouldBeCalled()->willReturn(
            new AuthenticationResponse(false, ADResponseCodes::RESPONSE_MESSAGE[ADResponseCodes::ACCOUNT_DISABLED], ADResponseCodes::ACCOUNT_DISABLED)
        );
        $this->shouldThrow('Symfony\Component\Security\Core\Exception\DisabledException')->duringCheckCredentials($this->credentials, $user);
        
        $this->connection->execute(new AuthenticationOperation('foo', 'bar'))->shouldBeCalled()->willThrow(new LdapConnectionException('unavailable'));
        $this->shouldThrow(new CustomUserMessageAuthenticationException('unavailable'))->duringCheckCredentials($this->credentials, $user);
    }

    function it_should_switch_the_domain_name_when_authenticating_a_user_and_the_domain_parameter_is_set()
    {
        $credentials = $this->credentials;
        $credentials['ldap_domain'] = 'foo.local';
        $user = new LdapUser(New LdapObject(['username' => 'foo']));

        $this->ldap->switchDomain('foo.local')->shouldBeCalled();
        $this->connection->execute(new AuthenticationOperation('foo', 'bar'))->shouldBeCalled()->willReturn(new AuthenticationResponse(true));
        $this->checkCredentials($credentials, $user)->shouldReturn(true);
    }

    /**
     * @param \Symfony\Component\Security\Core\User\UserProviderInterface $up
     */
    function it_should_throw_bad_credentials_if_a_specified_domain_doesnt_exist_on_user_load_or_authenticate($up)
    {
        $credentials = $this->credentials;
        $credentials['ldap_domain'] = 'foo.local';
        $user = new LdapUser(New LdapObject(['username' => 'foo']));

        $this->ldap->switchDomain('foo.local')->willThrow(new InvalidArgumentException('invalid'));
        $this->shouldThrow('Symfony\Component\Security\Core\Exception\BadCredentialsException')->duringCheckCredentials($credentials, $user);
        $this->shouldThrow('Symfony\Component\Security\Core\Exception\BadCredentialsException')->duringGetUser($credentials, $up);
    }
    
    /**
     * @param \Symfony\Component\Security\Core\Authentication\Token\TokenInterface $token
     */
    function it_should_return_the_correct_redirect_response_after_authentication_success($token)
    {
        $session = new Session();
        $this->request->setSession($session);
        
        $this->onAuthenticationSuccess($this->request, $token, 'foo')->getTargetUrl()->shouldEqual('/');
        $session->set('_security.main.target_path', '/foo');
        $this->onAuthenticationSuccess($this->request, $token, 'foo')->getTargetUrl()->shouldEqual('/foo');
    }

    /**
     * @param \Symfony\Component\HttpFoundation\Request $request
     * @param \Symfony\Component\HttpFoundation\Session\Session $session
     */
    function it_should_return_the_correct_redirect_response_after_authentication_failure($request, $session)
    {
        $request->getSession()->willReturn($session);
        $session->set('_security.last_error', Argument::type('Symfony\Component\Security\Core\Exception\AuthenticationException'))->shouldBeCalled();

        $this->onAuthenticationFailure($request, new AuthenticationException('foo'))->getTargetUrl()->shouldEqual('/login');
    }

    function it_should_return_false_for_supporting_remember_me()
    {
        $this->supportsRememberme()->shouldBeEqualTo(false);
    }

    /**
     * @param \Symfony\Component\Security\Core\User\UserInterface $user
     */
    function it_should_create_an_authentication_token_with_the_domain_name($user)
    {
        $user->getUsername()->shouldBeCalled()->willReturn('foo');
        $user->getRoles()->shouldBeCalled()->willReturn(['USER']);
        $this->connection->execute(new AuthenticationOperation('foo', 'bar'))->shouldBeCalled()->willReturn(new AuthenticationResponse(true));

        $this->checkCredentials(['username' => 'foo', 'password' => 'bar', 'domain' => ''], $user);
        $this->createAuthenticatedToken($user, 'foo')->shouldReturnAnInstanceOf('Symfony\Component\Security\Guard\Token\PostAuthenticationGuardToken');
        $this->createAuthenticatedToken($user, 'foo')->getAttribute('ldap_domain')->shouldEqual('foo.bar');
    }

    function it_should_return_a_redirect_response_on_start()
    {
        $this->start($this->request, null)->shouldReturnAnInstanceOf('Symfony\Component\HttpFoundation\RedirectResponse');   
    }
    
    function it_should_set_a_start_path()
    {
        $this->setStartPath('foo');
        
        $this->router->generate('foo')->shouldBeCalled()->willReturn('/foo');
        $this->start($this->request, null)->getTargetUrl()->shouldEqual('/foo');
    }
    
    function it_should_call_a_login_success_event()
    {
        $credentials = $this->credentials;
        $credentials['ldap_domain'] = '';
        $user = new LdapUser(New LdapObject(['username' => 'foo']));
        $token = new UsernamePasswordToken($user, $credentials['password'], 'ldap-tools', $user->getRoles());
        $token->setAttribute('ldap_domain', '');

        $this->connection->execute(new AuthenticationOperation('foo', 'bar'))->shouldBeCalled()->willReturn(new AuthenticationResponse(true));
        $this->checkCredentials($credentials, $user)->shouldReturn(true);
        
        $this->dispatcher->dispatch('ldap_tools_bundle.login.success', new LdapLoginEvent($user, $token))->shouldBeCalled();
    }
}
