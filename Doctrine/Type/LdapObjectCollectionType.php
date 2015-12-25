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

use Doctrine\DBAL\Types\ArrayType;

/**
 * More or less serves as an alias for an array type for storing a collection of LdapObject's.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class LdapObjectCollectionType extends ArrayType
{
    const TYPE = 'ldap_object_collection';

    /**
     * @inheritdoc
     */
    public function getName()
    {
        return self::TYPE;
    }
}
