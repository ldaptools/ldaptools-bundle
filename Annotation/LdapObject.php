<?php
/**
 * This file is part of the LdapToolsBundle package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace LdapTools\Bundle\LdapToolsBundle\Annotation;

/**
 * @Annotation
 * @Target("PROPERTY")
 */
class LdapObject
{
    /**
     * @Required
     * @var string
     */
    public $type;

    /**
     * @var string
     */
    public $domain;

    /**
     * @var string
     */
    public $id = 'guid';

    /**
     * @var bool
     */
    public $collection = false;

    /**
     * @var array
     */
    public $attributes = [];
}
