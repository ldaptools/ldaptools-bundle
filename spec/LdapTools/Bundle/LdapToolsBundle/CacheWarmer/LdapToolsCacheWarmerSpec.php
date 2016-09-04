<?php
/**
 * This file is part of the LdapToolsBundle package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace spec\LdapTools\Bundle\LdapToolsBundle\CacheWarmer;

use LdapTools\Configuration;
use LdapTools\DomainConfiguration;
use LdapTools\Factory\LdapObjectSchemaFactory;
use LdapTools\LdapManager;
use LdapTools\Schema\LdapObjectSchema;
use LdapTools\Schema\Parser\SchemaParserInterface;
use PhpSpec\ObjectBehavior;

class LdapToolsCacheWarmerSpec extends ObjectBehavior
{
    function let(LdapManager $ldap, Configuration $configuration)
    {
        $this->beConstructedWith($ldap, $configuration);
    }

    function it_is_initializable()
    {
        $this->shouldHaveType('LdapTools\Bundle\LdapToolsBundle\CacheWarmer\LdapToolsCacheWarmer');
    }

    function it_should_be_optional()
    {
        $this->isOptional()->shouldBeEqualTo(true);
    }

    function it_should_warm_up_the_cache($ldap, $configuration, SchemaParserInterface $parser, LdapObjectSchemaFactory $schemaFactory)
    {
        $ldap->getSchemaParser()->willReturn($parser);
        $ldap->getDomainContext()->willReturn('foo');
        $ldap->getSchemaFactory()->willReturn($schemaFactory);

        // It will switch to each domain as it loops. But it should call the original context twice...
        $ldap->switchDomain('foo')->shouldBeCalledTimes(2);
        $ldap->switchDomain('bar')->shouldBeCalledTimes(1);

        // When the schema factory get is called it will take care of the caching...
        $schemaFactory->get('ad', 'foo')->shouldBeCalled()->willReturn(null);
        $schemaFactory->get('openldap', 'bar')->shouldBeCalled()->willReturn(null);

        $domainOne = new DomainConfiguration('foo');
        $domainTwo = (new DomainConfiguration('bar'))->setLdapType('openldap');
        $configuration->getDomainConfiguration()->willReturn([$domainOne, $domainTwo]);

        $parser->parseAll('ad')->shouldBeCalled()->willReturn([new LdapObjectSchema('ad', 'foo')]);
        $parser->parseAll('openldap')->shouldBeCalled()->willReturn([new LdapObjectSchema('openldap', 'bar')]);

        $this->warmUp('/foo');
    }
}
