<?php
/**
 * This file is part of the LdapToolsBundle package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace LdapTools\Bundle\LdapToolsBundle\Doctrine\Type;

use Doctrine\DBAL\Types\TextType;

/**
 * More or less serves as an alias for a text type to store a single LdapObject.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class LdapObjectType extends TextType
{
    const TYPE = 'ldap_object';

    /**
     * @inheritdoc
     */
    public function getName()
    {
        return self::TYPE;
    }
}
