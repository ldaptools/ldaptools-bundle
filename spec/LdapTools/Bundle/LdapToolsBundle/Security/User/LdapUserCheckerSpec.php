<?php
/**
 * This file is part of the LdapToolsBundle package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace spec\LdapTools\Bundle\LdapToolsBundle\Security\User;

use LdapTools\Bundle\LdapToolsBundle\Security\User\LdapUser;
use LdapTools\Connection\ADResponseCodes;
use LdapTools\Connection\LdapConnection;
use PhpSpec\ObjectBehavior;
use Prophecy\Argument;

class LdapUserCheckerSpec extends ObjectBehavior
{
    function it_is_initializable()
    {
        $this->shouldHaveType('LdapTools\Bundle\LdapToolsBundle\Security\User\LdapUserChecker');
    }

    function it_should_implement_the_UserCheckerInterface()
    {
        $this->shouldImplement('\Symfony\Component\Security\Core\User\UserCheckerInterface');
    }

    function it_should_extend_the_UserChecker()
    {
        $this->shouldBeAnInstanceOf('\Symfony\Component\Security\Core\User\UserChecker');
    }

    function it_should_error_when_the_response_code_for_the_user_is_for_a_disabled_account(LdapUser $user)
    {
        $this->shouldThrow('\Symfony\Component\Security\Core\Exception\DisabledException')->duringCheckLdapErrorCode(
            $user,
            ADResponseCodes::ACCOUNT_DISABLED,
            LdapConnection::TYPE_AD
        );
    }

    function it_should_not_error_when_the_response_code_is_the_same_value_as_disabled_for_something_other_than_AD(LdapUser $user)
    {
        $this->shouldNotThrow('\Symfony\Component\Security\Core\Exception\DisabledException')->duringCheckLdapErrorCode(
            $user,
            ADResponseCodes::ACCOUNT_DISABLED,
            LdapConnection::TYPE_OPENLDAP
        );
    }

    function it_should_error_when_the_response_code_for_the_user_is_for_a_locked_account(LdapUser $user)
    {
        $this->shouldThrow('\Symfony\Component\Security\Core\Exception\LockedException')->duringCheckLdapErrorCode(
            $user,
            ADResponseCodes::ACCOUNT_LOCKED,
            LdapConnection::TYPE_AD
        );
    }

    function it_should_not_error_when_the_response_code_is_the_same_value_as_locked_for_something_other_than_AD(LdapUser $user)
    {
        $this->shouldNotThrow('\Symfony\Component\Security\Core\Exception\LockedException')->duringCheckLdapErrorCode(
            $user,
            ADResponseCodes::ACCOUNT_LOCKED,
            LdapConnection::TYPE_OPENLDAP
        );
    }

    function it_should_throw_CredentialsExpired_when_the_response_code_for_the_user_is_for_an_account_whose_password_must_change(LdapUser $user)
    {
        $this->shouldThrow('\Symfony\Component\Security\Core\Exception\CredentialsExpiredException')->duringCheckLdapErrorCode(
            $user,
            ADResponseCodes::ACCOUNT_PASSWORD_MUST_CHANGE,
            LdapConnection::TYPE_AD
        );
    }

    function it_should_not_throw_CredentialsExpired_when_the_response_code_is_the_same_value_as_pass_must_change_for_something_other_than_AD(LdapUser $user)
    {
        $this->shouldNotThrow('\Symfony\Component\Security\Core\Exception\CredentialsExpiredException')->duringCheckLdapErrorCode(
            $user,
            ADResponseCodes::ACCOUNT_PASSWORD_MUST_CHANGE,
            LdapConnection::TYPE_OPENLDAP
        );
    }
}
