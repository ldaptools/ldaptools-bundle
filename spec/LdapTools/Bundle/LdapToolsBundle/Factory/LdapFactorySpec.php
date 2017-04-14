<?php
/**
 * This file is part of the LdapToolsBundle package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace spec\LdapTools\Bundle\LdapToolsBundle\Factory;

use LdapTools\Bundle\LdapToolsBundle\Factory\LdapFactory;
use LdapTools\DomainConfiguration;
use PhpSpec\ObjectBehavior;
use Prophecy\Argument;

class LdapFactorySpec extends ObjectBehavior
{
    function it_is_initializable()
    {
        $this->shouldHaveType(LdapFactory::class);
    }

    function it_should_get_a_domain_configuration()
    {
        $this->getConfig('foo')->shouldReturnAnInstanceOf('LdapTools\DomainConfiguration');
    }

    function it_should_get_a_ldap_connection()
    {
        $this->getConnection((new DomainConfiguration('foo'))->setLazyBind(true))
            ->shouldReturnAnInstanceOf('LdapTools\Connection\LdapConnectionInterface');
    }
}
