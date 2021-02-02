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
use LdapTools\Bundle\LdapToolsBundle\Security\User\LdapUserProvider;
use LdapTools\Enums\AD\ResponseCode;
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
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\Session\Session;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;
use Symfony\Component\Security\Core\Exception\CustomUserMessageAuthenticationException;
use Symfony\Component\Security\Core\Exception\UsernameNotFoundException;
use Symfony\Component\Security\Core\User\User;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Http\Authentication\DefaultAuthenticationFailureHandler;
use Symfony\Component\Security\Http\Authentication\DefaultAuthenticationSuccessHandler;
use Symfony\Component\Security\Http\EntryPoint\AuthenticationEntryPointInterface;

/**
 * @require Symfony\Component\Security\Guard\AbstractGuardAuthenticator
 */
class LdapGuardAuthenticatorSpec extends ObjectBehavior
{
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
    
    function let(LdapManager $ldap, LdapConnectionInterface $connection, AuthenticationEntryPointInterface $entryPoint, EventDispatcherInterface $dispatcher, DefaultAuthenticationSuccessHandler $authSuccess, DefaultAuthenticationFailureHandler $authFailure, LdapUserProvider $ldapUserProvider)
    {
        $this->userChecker = new LdapUserChecker();
        $this->request = new Request();
        $this->request->setSession(new Session());

        $config = (new DomainConfiguration('foo.bar'))->setUsername('foo')->setPassword('bar');
        $entryPoint->start(Argument::any(), Argument::any())->willReturn(new RedirectResponse('/foo'));
        $connection->getConfig()->willReturn($config);
        $ldap->getConnection()->willReturn($connection);
        $ldap->getDomainContext()->willReturn('foo.bar');
        $authFailure->onAuthenticationFailure(Argument::any(), Argument::any())->willReturn(RedirectResponse::create('/'));
        $authSuccess->onAuthenticationSuccess(Argument::any(), Argument::any())->willReturn(RedirectResponse::create('/'));

        $this->beConstructedWith(true, $this->userChecker, $ldap, $entryPoint, $dispatcher, $authSuccess, $authFailure, ['hide_user_not_found_exceptions' => true], $ldapUserProvider);
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

    function it_should_get_the_credentials_array_with_http_basic($ldap, $entryPoint, $dispatcher, $authSuccess, $authFailure, $ldapUserProvider)
    {
        $this->beConstructedWith(false, $this->userChecker, $ldap, $entryPoint, $dispatcher, $authSuccess, $authFailure,  ['http_basic' => true], $ldapUserProvider);

        $this->request->server->add(['PHP_AUTH_USER' => 'foo', 'PHP_AUTH_PW' => 'bar']);

        $this->getCredentials($this->request)->shouldBeEqualTo(['username' => 'foo', 'password' => 'bar', 'ldap_domain' => null]);
    }

    function it_should_get_the_domain_in_the_credentials_array_with_http_basic_if_specified($ldap, $entryPoint, $dispatcher, $authSuccess, $authFailure, $ldapUserProvider)
    {
        $this->beConstructedWith(false, $this->userChecker, $ldap, $entryPoint, $dispatcher, $authSuccess, $authFailure,  ['http_basic' => true, 'http_basic_domain' => 'foo.bar'], $ldapUserProvider);

        $this->request->server->add(['PHP_AUTH_USER' => 'foo', 'PHP_AUTH_PW' => 'bar']);

        $this->getCredentials($this->request)->shouldHaveKeyWithValue('ldap_domain', 'foo.bar');
    }

    function it_should_get_null_when_getting_the_credentials_array_with_no_username_set()
    {
        $this->getCredentials($this->request)->shouldBeNull();
    }

    function it_should_get_a_user_object(LdapUserProvider $up, $ldap, DomainConfiguration $dc, $connection)
    {
        $credentials = $this->credentials;
        $credentials['ldap_domain'] = '';
        $user = (new LdapUser())->refresh(['username' => 'foo', 'guid' => 'bar']);

        $ldap->switchDomain(Argument::any())->shouldNotBeCalled();
        $up->loadUserByUsername('foo')->shouldBeCalled()->willReturn($user);

        $connection->getConfig()->willReturn($dc);
        $dc->getPassword()->willReturn('foo');
        $dc->getUsername()->willReturn('bar');

        $dc->setUsername(Argument::any())->shouldNotBeCalled();
        $dc->setPassword(Argument::any())->shouldNotBeCalled();

        $this->getUser($this->credentials, $up)->shouldBeEqualTo($user);
    }

    function it_should_throw_an_exception_when_a_username_isnt_found(UserProviderInterface $up)
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

    function it_should_not_hide_the_exception_message_when_specified(UserProviderInterface $up, $ldap, $entryPoint, $dispatcher, $authSuccess, $authFailure, $ldapUserProvider)
    {
        $credentials = $this->credentials;
        $credentials['ldap_domain'] = '';
        $this->beConstructedWith(false, $this->userChecker, $ldap, $entryPoint, $dispatcher, $authSuccess, $authFailure,  [], $ldapUserProvider);

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

    function it_should_throw_an_exception_when_a_user_is_loaded_that_is_disabled_or_locked(UserProviderInterface $up, $ldap, $entryPoint, $dispatcher, $authSuccess, $authFailure, $ldapUserProvider)
    {
        $credentials = $this->credentials;
        $credentials['ldap_domain'] = '';
        $this->beConstructedWith(false, $this->userChecker, $ldap, $entryPoint, $dispatcher, $authSuccess, $authFailure, [], $ldapUserProvider);
        
        $user = (new LdapUser())->refresh([
            'username' => 'foo',
            'enabled' => false,
        ]);
        $up->loadUserByUsername('foo')->shouldBeCalled()->willReturn($user);
        $this->shouldThrow('Symfony\Component\Security\Core\Exception\DisabledException')->duringGetUser($this->credentials, $up);

        $user = (new LdapUser())->refresh([
            'username' => 'foo',
            'locked' => true,
        ]);
        $up->loadUserByUsername('foo')->shouldBeCalled()->willReturn($user);
        $this->shouldThrow('Symfony\Component\Security\Core\Exception\LockedException')->duringGetUser($this->credentials, $up);
    }

    function it_should_switch_the_domain_name_when_loading_a_user_if_the_domain_parameter_is_set(UserProviderInterface $up, $connection, $ldap)
    {
        $credentials = $this->credentials;
        $credentials['ldap_domain'] = 'foo.local';
        $user = new LdapUser(New LdapObject(['username' => 'foo']));

        $ldap->switchDomain('foo.local')->shouldBeCalled()->willReturn($connection);
        $up->loadUserByUsername('foo')->shouldBeCalled()->willReturn($user);

        $this->getUser($credentials, $up)->shouldBeEqualTo($user);
    }

    function it_should_check_the_credentials_of_a_loaded_user($connection)
    {
        $credentials = $this->credentials;
        $credentials['ldap_domain'] = '';
        $user = (new LdapUser())->refresh(['username' => 'foo', 'guid' => 'foo']);

        $connection->execute(new AuthenticationOperation('foo', 'bar'))->shouldBeCalled()->willReturn(new AuthenticationResponse(true));
        $this->checkCredentials($credentials, $user)->shouldReturn(true);
    }

    function it_should_throw_an_exception_if_checking_credentials_fails($connection)
    {
        $credentials = $this->credentials;
        $credentials['ldap_domain'] = '';
        $user = (new LdapUser())->refresh(['guid' => 'foo', 'username' => 'foo']);

        $connection->execute(new AuthenticationOperation('foo', 'bar'))->shouldBeCalled()->willReturn(new AuthenticationResponse(false, 'foo', 1));
        $this->shouldThrow('Symfony\Component\Security\Core\Exception\BadCredentialsException')->duringCheckCredentials($credentials, $user);

        $connection->execute(new AuthenticationOperation('foo', 'bar'))->shouldBeCalled()->willReturn(new AuthenticationResponse(false, 'foo', ResponseCode::AccountDisabled));
        $this->shouldThrow('Symfony\Component\Security\Core\Exception\BadCredentialsException')->duringCheckCredentials($credentials, $user);
    }
    
    function it_should_not_mask_the_error_message_when_checking_credentials_if_specified($ldap, $entryPoint, $dispatcher, $connection, $authSuccess, $authFailure, $ldapUserProvider)
    {
        $credentials = $this->credentials;
        $credentials['ldap_domain'] = '';
        $this->beConstructedWith(false, $this->userChecker, $ldap, $entryPoint, $dispatcher, $authSuccess, $authFailure,  [], $ldapUserProvider);
        $user = (new LdapUser())->refresh(['guid' => 'foo', 'username' => 'foo']);
        
        $connection->execute(new AuthenticationOperation('foo', 'bar'))->shouldBeCalled()->willReturn(
            new AuthenticationResponse(false, ResponseCode::getMessageForError(ResponseCode::AccountPasswordMustChange), ResponseCode::AccountPasswordMustChange)
        );
        $this->shouldThrow('Symfony\Component\Security\Core\Exception\CredentialsExpiredException')->duringCheckCredentials($this->credentials, $user);

        $connection->execute(new AuthenticationOperation('foo', 'bar'))->shouldBeCalled()->willReturn(
            new AuthenticationResponse(false, ResponseCode::getMessageForError(ResponseCode::AccountDisabled), ResponseCode::AccountDisabled)
        );
        $this->shouldThrow('Symfony\Component\Security\Core\Exception\DisabledException')->duringCheckCredentials($this->credentials, $user);
        
        $connection->execute(new AuthenticationOperation('foo', 'bar'))->shouldBeCalled()->willThrow(new LdapConnectionException('unavailable'));
        $this->shouldThrow(new CustomUserMessageAuthenticationException('unavailable'))->duringCheckCredentials($this->credentials, $user);
    }

    function it_should_switch_the_domain_name_when_authenticating_a_user_and_the_domain_parameter_is_set($ldap, $connection)
    {
        $credentials = $this->credentials;
        $credentials['ldap_domain'] = 'foo.local';
        $user = (new LdapUser())->refresh(['guid' => 'foo', 'username' => 'foo']);

        $ldap->switchDomain('foo.local')->shouldBeCalled();
        $connection->execute(new AuthenticationOperation('foo', 'bar'))->shouldBeCalled()->willReturn(new AuthenticationResponse(true));
        $this->checkCredentials($credentials, $user)->shouldReturn(true);
    }

    function it_should_throw_bad_credentials_if_a_specified_domain_doesnt_exist_on_user_load_or_authenticate(UserProviderInterface $up, $ldap)
    {
        $credentials = $this->credentials;
        $credentials['ldap_domain'] = 'foo.local';
        $user = (new LdapUser())->refresh(['guid' => 'foo', 'username' => 'foo']);

        $ldap->switchDomain('foo.local')->willThrow(new InvalidArgumentException('invalid'));
        $this->shouldThrow('Symfony\Component\Security\Core\Exception\BadCredentialsException')->duringCheckCredentials($credentials, $user);
        $this->shouldThrow('Symfony\Component\Security\Core\Exception\BadCredentialsException')->duringGetUser($credentials, $up);
    }
    
    function it_should_return_a_redirect_response_after_authentication_success(TokenInterface $token)
    {
        $this->onAuthenticationSuccess($this->request, $token, 'main')->shouldReturnAnInstanceOf('Symfony\Component\HttpFoundation\RedirectResponse');
    }

    function it_should_return_the_correct_redirect_response_after_authentication_failure(Request $request)
    {
        $this->onAuthenticationFailure($request, new AuthenticationException('foo'))->shouldReturnAnInstanceOf('Symfony\Component\HttpFoundation\RedirectResponse');
    }

    function it_should_create_an_authentication_token_with_the_domain_name(UserInterface $user, $connection)
    {
        $user->getUsername()->shouldBeCalled()->willReturn('foo');
        $user->getRoles()->shouldBeCalled()->willReturn(['USER']);
        $connection->execute(new AuthenticationOperation('foo', 'bar'))->shouldBeCalled()->willReturn(new AuthenticationResponse(true));

        $this->checkCredentials(['username' => 'foo', 'password' => 'bar', 'domain' => ''], $user);
        $this->createAuthenticatedToken($user, 'foo')->shouldReturnAnInstanceOf('Symfony\Component\Security\Guard\Token\PostAuthenticationGuardToken');
        $this->createAuthenticatedToken($user, 'foo')->getAttribute('ldap_domain')->shouldEqual('foo.bar');
    }

    function it_should_return_a_redirect_response_on_start()
    {
        $this->start($this->request, null)->shouldReturnAnInstanceOf('Symfony\Component\HttpFoundation\RedirectResponse');   
    }

    function it_should_obey_the_post_only_option($ldap, $entryPoint, $dispatcher, $authSuccess, $authFailure, $ldapUserProvider)
    {
        $this->beConstructedWith(false, $this->userChecker, $ldap, $entryPoint, $dispatcher, $authSuccess, $authFailure,  ['post_only' => true], $ldapUserProvider);
        $this->request->query->add(['_username' => 'foo', '_password' => 'bar']);

        $this->getCredentials($this->request)->shouldBeNull();
    }

    function it_should_not_support_remember_me_by_defult()
    {
        $this->supportsRememberMe()->shouldBeEqualTo(false);
    }

    function it_should_support_remember_me_if_specified($ldap, $entryPoint, $dispatcher, $authSuccess, $authFailure, $ldapUserProvider)
    {
        $this->beConstructedWith(false, $this->userChecker, $ldap, $entryPoint, $dispatcher, $authSuccess, $authFailure,  ['remember_me' => true], $ldapUserProvider);

        $this->supportsRememberMe()->shouldBeEqualTo(true);
    }

    function it_should_call_a_login_success_event($connection, $dispatcher)
    {
        $credentials = $this->credentials;
        $credentials['ldap_domain'] = '';
        $user = (new LdapUser())->refresh(['guid' => 'foo', 'username' => 'foo']);
        $token = new UsernamePasswordToken($user, $credentials['password'], 'ldap-tools', $user->getRoles());
        $token->setAttribute('ldap_domain', '');

        $connection->execute(new AuthenticationOperation('foo', 'bar'))->shouldBeCalled()->willReturn(new AuthenticationResponse(true));
        $this->checkCredentials($credentials, $user)->shouldReturn(true);

        $dispatcher->dispatch(new LdapLoginEvent($user, $token), 'ldap_tools_bundle.login.success')->shouldBeCalled();
    }

    function it_should_call_an_auth_success_handler_event(Request $request, $dispatcher, TokenInterface $token)
    {
        $dispatcher->dispatch(Argument::type('LdapTools\Bundle\LdapToolsBundle\Event\AuthenticationHandlerEvent'), 'ldap_tools_bundle.guard.login.success')->shouldBeCalled();

        $this->onAuthenticationSuccess($request, $token, 'foo');
    }

    function it_should_call_an_auth_failure_handler_event(Request $request, $dispatcher)
    {
        $dispatcher->dispatch(Argument::type('LdapTools\Bundle\LdapToolsBundle\Event\AuthenticationHandlerEvent'), 'ldap_tools_bundle.guard.login.failure')->shouldBeCalled();

        $this->onAuthenticationFailure($request, new AuthenticationException('foo'));
    }

    function it_should_call_an_auth_start_event(Request $request, $dispatcher)
    {
        $dispatcher->dispatch(Argument::type('LdapTools\Bundle\LdapToolsBundle\Event\AuthenticationHandlerEvent'), 'ldap_tools_bundle.guard.login.start')->shouldBeCalled();

        $this->start($request, new AuthenticationException('foo'));
    }

    function it_should_use_user_supplied_credentials_for_the_user_provider_if_the_domain_config_has_no_credentials_defined(LdapUserProvider $up, $connection, DomainConfiguration $dc)
    {
        $user = (new LdapUser())->refresh(['username' => 'foo', 'guid' => 'bar']);
        $up->loadUserByUsername('foo')->shouldBeCalled()->willReturn($user);

        $connection->getConfig()->willReturn($dc);
        $dc->getPassword()->willReturn(null);
        $dc->getUsername()->willReturn(null);

        $dc->setUsername('foo')->shouldBeCalled();
        $dc->setPassword('bar')->shouldBeCalled();

        $this->getUser(['username' => 'foo', 'password' => 'bar', 'ldap_domain' => ''], $up)->shouldBeEqualTo($user);
    }

    function it_should_query_LDAP_for_the_username_on_login_for_the_bind_DN_if_specified($ldap, $entryPoint, $dispatcher, $authSuccess, $authFailure, $ldapUserProvider, $connection)
    {
        $this->beConstructedWith(false, $this->userChecker, $ldap, $entryPoint, $dispatcher, $authSuccess, $authFailure, ['login_query_attribute' => 'username'], $ldapUserProvider);

        $credentials = $this->credentials;
        $credentials['ldap_domain'] = '';

        $user = new User('foo', null);
        $ldapUserProvider->getLdapUser('username', 'foo')->shouldBeCalled()->willReturn(new LdapObject(['dn' => 'cn=foo,dc=foo,dc=bar'], 'user'));

        $connection->execute(new AuthenticationOperation('cn=foo,dc=foo,dc=bar', 'bar'))->shouldBeCalled()->willReturn(new AuthenticationResponse(true));

        $this->checkCredentials($credentials, $user)->shouldReturn(true);
    }

    function it_should_prefer_to_use_the_users_DN_on_login_if_available($connection)
    {
        $credentials = $this->credentials;
        $credentials['ldap_domain'] = '';
        $user = (new LdapUser())->refresh(['username' => 'foo', 'guid' => 'foo', 'dn' => 'cn=foo,dc=foo,dc=bar']);

        $connection->execute(new AuthenticationOperation('cn=foo,dc=foo,dc=bar', 'bar'))->shouldBeCalled()->willReturn(new AuthenticationResponse(true));
        $this->checkCredentials($credentials, $user)->shouldReturn(true);
    }

    function it_should_use_http_basic_authentication_on_start_if_specified($ldap, $entryPoint, $dispatcher, $authSuccess, $authFailure, $ldapUserProvider)
    {
        $this->beConstructedWith(false, $this->userChecker, $ldap, $entryPoint, $dispatcher, $authSuccess, $authFailure,  ['http_basic' => true], $ldapUserProvider);

        $response = new Response();
        $response->headers->set('WWW-Authenticate', 'Basic realm="foo.bar"');
        $response->setStatusCode(401);

        $this->start($this->request, null)->shouldBeLike($response);
    }

    function it_should_return_null_when_using_http_basic_on_authentication_success(Request $request, $ldap, $entryPoint, $dispatcher, $authSuccess, $authFailure, $ldapUserProvider, TokenInterface $token)
    {
        $this->beConstructedWith(false, $this->userChecker, $ldap, $entryPoint, $dispatcher, $authSuccess, $authFailure,  ['http_basic' => true], $ldapUserProvider);

        $this->onAuthenticationSuccess($request, $token, 'main')->shouldBeNull();
    }

    function it_should_return_null_when_using_http_basic_on_authentication_failure(Request $request, $ldap, $entryPoint, $dispatcher, $authSuccess, $authFailure, $ldapUserProvider)
    {
        $this->beConstructedWith(false, $this->userChecker, $ldap, $entryPoint, $dispatcher, $authSuccess, $authFailure,  ['http_basic' => true], $ldapUserProvider);

        $this->onAuthenticationFailure($request, new AuthenticationException('foo'))->shouldBeNull();
    }

    function it_should_set_the_http_basic_realm_if_specified($ldap, $entryPoint, $dispatcher, $authSuccess, $authFailure, $ldapUserProvider)
    {
        $this->beConstructedWith(false, $this->userChecker, $ldap, $entryPoint, $dispatcher, $authSuccess, $authFailure,  ['http_basic' => true, 'http_basic_realm' => 'Secret Area'], $ldapUserProvider);

        $response = new Response();
        $response->headers->set('WWW-Authenticate', 'Basic realm="Secret Area"');
        $response->setStatusCode(401);

        $this->start($this->request, null)->shouldBeLike($response);
    }

    function it_should_allow_setting_options_via_the_setOptions_method()
    {
        $this->setOptions(['username_parameter' => '_foo']);
        $this->request->request->add([
            '_foo' => 'foo',
            '_password' => 'bar',
            '_ldap_domain' => 'foo.bar',
        ]);

        $this->getCredentials($this->request)->shouldHaveKeyWithValue('username','foo');
    }

    function it_should_check_whether_the_request_is_supported()
    {
        $this->request->request->add([]);
        $this->supports($this->request)->shouldBeEqualTo(false);

        $this->request->request->add(['_username' => 'foo']);
        $this->supports($this->request)->shouldBeEqualTo(true);
    }
}
