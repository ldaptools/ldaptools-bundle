<?php
/**
 * This file is part of the LdapToolsBundle package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace spec\LdapTools\Bundle\LdapToolsBundle\Doctrine\Type;

use Doctrine\DBAL\Types\Type;
use LdapTools\Bundle\LdapToolsBundle\Doctrine\Type\LdapObjectCollectionType;
use PhpSpec\ObjectBehavior;
use Prophecy\Argument;

class LdapObjectCollectionTypeSpec extends ObjectBehavior
{
    function let()
    {
        $type = LdapObjectCollectionType::TYPE;

        if (!Type::hasType($type)) {
            Type::addType($type, '\LdapTools\Bundle\LdapToolsBundle\Doctrine\Type\LdapObjectCollectionType');
        }

        $this->beConstructedThrough('getType', [$type]);
    }

    function it_is_initializable()
    {
        $this->shouldHaveType('LdapTools\Bundle\LdapToolsBundle\Doctrine\Type\LdapObjectCollectionType');
    }

    function it_should_extend_the_DBAL_array_type()
    {
        $this->shouldBeAnInstanceOf('\Doctrine\DBAL\Types\ArrayType');
    }

    function it_should_get_the_name()
    {
        $this->getName()->shouldBeEqualTo('ldap_object_collection');
    }
}
