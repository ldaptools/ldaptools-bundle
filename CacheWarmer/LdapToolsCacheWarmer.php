<?php
/**
 * This file is part of the LdapToolsBundle package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace LdapTools\Bundle\LdapToolsBundle\CacheWarmer;

use LdapTools\Configuration;
use LdapTools\Factory\LdapObjectSchemaFactory;
use LdapTools\LdapManager;
use LdapTools\Schema\LdapObjectSchema;
use Symfony\Component\HttpKernel\CacheWarmer\CacheWarmerInterface;

/**
 * A cache warmer for the LDAP schema types.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class LdapToolsCacheWarmer implements CacheWarmerInterface
{
    /**
     * @var LdapManager
     */
    protected $ldap;

    /**
     * @var Configuration
     */
    protected $config;

    /**
     * @param LdapManager $ldap
     * @param Configuration $config
     */
    public function __construct(LdapManager $ldap, Configuration $config)
    {
        $this->ldap = $ldap;
        $this->config = $config;
    }

    /**
     * {@inheritdoc}
     */
    public function warmUp($cacheDir)
    {
        $domain = $this->ldap->getDomainContext();
        foreach ($this->config->getDomainConfiguration() as $domainConfig) {
            $this->ldap->switchDomain($domainConfig->getDomainName());
            $schemaFactory = $this->ldap->getSchemaFactory();
            $parser = $this->ldap->getSchemaParser();
            $schema = empty($domainConfig->getSchemaName()) ? $domainConfig->getLdapType() : $domainConfig->getSchemaName();
            $ldapObjects = $parser->parseAll($schema);

            $this->cacheAllLdapSchemaObjects($schemaFactory, ...$ldapObjects);
        }
        $this->ldap->switchDomain($domain);
    }

    /**
     * {@inheritdoc}
     */
    public function isOptional()
    {
        return true;
    }

    /**
     * @param LdapObjectSchemaFactory $schemaFactory
     * @param LdapObjectSchema ...$schemaObjects
     */
    protected function cacheAllLdapSchemaObjects(LdapObjectSchemaFactory $schemaFactory, LdapObjectSchema ...$schemaObjects)
    {
        /** @var LdapObjectSchema $ldapSchemaObject */
        foreach ($schemaObjects as $ldapSchemaObject) {
            $schemaFactory->get($ldapSchemaObject->getSchemaName(), $ldapSchemaObject->getObjectType());
        }
    }
}
