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
use LdapTools\LdapManager;
use LdapTools\Schema\LdapObjectSchema;
use PhpSpec\ObjectBehavior;
use Prophecy\Argument;

class LdapToolsCacheWarmerSpec extends ObjectBehavior
{
    /**
     * @var LdapManager
     */
    protected $ldap;

    /**
     * @var Configuration
     */
    protected $configuration;

    /**
     * @param \LdapTools\LdapManager $ldapManager
     * @param \LdapTools\Configuration $configuration
     */
    function let($ldapManager, $configuration)
    {
        $this->configuration = $configuration;
        $this->ldap = $ldapManager;

        $this->beConstructedWith($ldapManager, $configuration);
    }

    function it_is_initializable()
    {
        $this->shouldHaveType('LdapTools\Bundle\LdapToolsBundle\CacheWarmer\LdapToolsCacheWarmer');
    }

    function it_should_be_optional()
    {
        $this->isOptional()->shouldBeEqualTo(true);
    }

    /**
     * @param \LdapTools\Schema\Parser\SchemaParserInterface $parser
     * @param \LdapTools\Factory\LdapObjectSchemaFactory $schemaFactory
     */
    function it_should_warm_up_the_cache($parser, $schemaFactory)
    {
        $this->ldap->getSchemaParser()->willReturn($parser);
        $this->ldap->getDomainContext()->willReturn('foo');
        $this->ldap->getSchemaFactory()->willReturn($schemaFactory);

        // It will switch to each domain as it loops. But it should call the original context twice...
        $this->ldap->switchDomain('foo')->shouldBeCalledTimes(2);
        $this->ldap->switchDomain('bar')->shouldBeCalledTimes(1);

        // When the schema factory get is called it will take care of the caching...
        $schemaFactory->get('ad', 'foo')->shouldBeCalled()->willReturn(null);
        $schemaFactory->get('openldap', 'bar')->shouldBeCalled()->willReturn(null);

        $domainOne = new DomainConfiguration('foo');
        $domainTwo = (new DomainConfiguration('bar'))->setLdapType('openldap');
        $this->configuration->getDomainConfiguration()->willReturn([$domainOne, $domainTwo]);

        $parser->parseAll('ad')->shouldBeCalled()->willReturn([new LdapObjectSchema('ad', 'foo')]);
        $parser->parseAll('openldap')->shouldBeCalled()->willReturn([new LdapObjectSchema('openldap', 'bar')]);

        $this->warmUp('/foo');
    }
}
