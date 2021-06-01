<?php
/**
 * This file is part of the LdapToolsBundle package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace LdapTools\Bundle\LdapToolsBundle\Doctrine\Subscriber;

use Doctrine\Common\Annotations\Reader;
use Doctrine\Common\EventSubscriber;
use Doctrine\Common\Persistence\ObjectManager;
use LdapTools\Bundle\LdapToolsBundle\Annotation\LdapObject as LdapObjectAnnotation;
use Doctrine\ORM\Event\LifecycleEventArgs;
use LdapTools\LdapManager;
use LdapTools\Object\LdapObject;
use LdapTools\Object\LdapObjectCollection;

/**
 * Doctrine Lifecycle Events to load/save LDAP objects to an entity property.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class LdapObjectSubscriber implements EventSubscriber
{
    /**
     * The annotation class to check for.
     */
    const ANNOTATION = 'LdapTools\Bundle\LdapToolsBundle\Annotation\LdapObject';

    /**
     * @var Reader
     */
    protected $reader;

    /**
     * @var LdapManager
     */
    protected $ldap;

    /**
     * @param Reader $reader
     * @param LdapManager $ldap
     */
    public function __construct(Reader $reader, LdapManager $ldap)
    {
        $this->reader = $reader;
        $this->ldap = $ldap;
    }

    /**
     * @return array
     */
    public function getSubscribedEvents()
    {
        return [
            'prePersist',
            'preUpdate',
            'postLoad',
        ];
    }

    /**
     * @param LifecycleEventArgs $args
     */
    public function preUpdate(LifecycleEventArgs $args)
    {
        $this->transformValueForDb($args);
    }

    /**
     * @param LifecycleEventArgs $args
     */
    public function prePersist(LifecycleEventArgs $args)
    {
        $this->transformValueForDb($args);
    }

    /**
     * @param LifecycleEventArgs $args
     */
    public function postLoad(LifecycleEventArgs $args)
    {
        $entity = $this->getObjectFromLifeCycleArgs($args);
        $om = $this->getOmFromLifeCycleArgs($args);

        $properties = $this->getLdapObjectAnnotationProperties($entity, $om);
        foreach ($properties as $info) {
            if ($info['property']->getValue($entity)) {
                $this->setLdapObjectForProperty($info['property'], $info['annotation'], $entity);
            }
        }
    }

    /**
     * Handles transforming the value as it currently is to the value the DB expects.
     *
     * @param LifecycleEventArgs $args
     */
    protected function transformValueForDb(LifecycleEventArgs $args)
    {
        $entity = $this->getObjectFromLifeCycleArgs($args);
        $om = $this->getOmFromLifeCycleArgs($args);

        $properties = $this->getLdapObjectAnnotationProperties($entity, $om);
        foreach ($properties as $info) {
            if ($info['property']->getValue($entity)) {
                $this->setLdapValueForProperty($info['property'], $info['annotation'], $entity);
            }
        }
    }

    /**
     * Get all the properties from the entity that have a LdapObject annotation defined.
     *
     * @param object $entity
     * @param ObjectManager $om
     * @return array
     */
    protected function getLdapObjectAnnotationProperties($entity, $om)
    {
        $properties = $om->getClassMetadata(get_class($entity))->getReflectionProperties();

        $ldapObjectProps = [];
        foreach ($properties as $prop) {
            $annotation = $this->reader->getPropertyAnnotation($prop, self::ANNOTATION);
            if (!empty($annotation)) {
                $ldapObjectProps[] = ['annotation' => $annotation, 'property' => $prop];
            }
        }

        return $ldapObjectProps;
    }

    /**
     * Based on an array of IDs for LDAP objects, set the property to either a LdapObject for LdapObjectCollection.
     *
     * @param \ReflectionProperty $property
     * @param LdapObjectAnnotation $annotation
     * @param $entity
     */
    protected function setLdapObjectForProperty(\ReflectionProperty $property, LdapObjectAnnotation $annotation, $entity)
    {
        if (empty($property->getValue($entity))) {
            return;
        }
        $domain = $this->ldap->getDomainContext();
        $switchDomain = $annotation->domain ?: null;
        if ($switchDomain) {
            $this->ldap->switchDomain($annotation->domain);
        }

        $results = $this->queryLdapForObjects($property, $annotation, $entity);
        $property->setValue($entity, $results);

        if ($switchDomain) {
            $this->ldap->switchDomain($domain);
        }
    }

    /**
     * Get the specified ID for each LDAP object and save it to an array.
     *
     * @param \ReflectionProperty $property
     * @param LdapObjectAnnotation $annotation
     * @param $entity
     */
    protected function setLdapValueForProperty(\ReflectionProperty $property, LdapObjectAnnotation $annotation, $entity)
    {
        $value = $property->getValue($entity);

        if ($value instanceof LdapObject) {
            $ldapValues = $value->get($annotation->id);
        } elseif ($value instanceof LdapObjectCollection) {
            $ldapValues = [];
            foreach ($value->toArray() as $ldapObject) {
                $ldapValues[] = $ldapObject->get($annotation->id);
            }
        } else {
            throw new \InvalidArgumentException(sprintf(
                'Class "%s" is not valid. Expected a LdapObject or LdapObjectCollection',
                get_class($value)
            ));
        }

        $property->setValue($entity, $ldapValues);
    }

    /**
     * @param LdapObjectAnnotation $annotation
     * @return array
     */
    protected function getLdapAttributesToSelect(LdapObjectAnnotation $annotation)
    {
        $attributes = $annotation->attributes;
        if (empty($attributes)) {
            $schemaFactory = $this->ldap->getSchemaFactory();
            $schema = $schemaFactory->get(
                $this->ldap->getConnection()->getConfig()->getSchemaName(),
                $annotation->type
            );
            $attributes = $schema->getAttributesToSelect();
        }

        if (!in_array($annotation->id, $attributes)) {
            $attributes[] = $annotation->id;
        }

        return $attributes;
    }

    /**
     * @param \ReflectionProperty $property
     * @param LdapObjectAnnotation $annotation
     * @param $entity
     * @return LdapObject|LdapObjectCollection|null
     */
    protected function queryLdapForObjects(\ReflectionProperty $property, LdapObjectAnnotation $annotation, $entity)
    {
        $query = $this->ldap->buildLdapQuery()
            ->select($this->getLdapAttributesToSelect($annotation))
            ->from($annotation->type);
        $values = $property->getValue($entity);

        // A single LdapObject type...
        if (is_string($values) && !empty($values)) {
            $query->where([$annotation->id => $values]);
        // A LdapObjectCollection type...
        } elseif (is_array($values) && !empty($values)) {
            foreach ($values as $value) {
                $query->orWhere([$annotation->id => $value]);
            }
        // A currently null/empty value?
        } else {
            return null;
        }

        if ($annotation->collection) {
            $results = $query->getLdapQuery()->getResult();
        } else {
            $results = $query->getLdapQuery()->getOneOrNullResult();
        }

        return $results;
    }

    /**
     * Avoid calling deprecated methods if possible.
     *
     * @param LifecycleEventArgs $args
     * @return object
     */
    protected function getObjectFromLifeCycleArgs(LifecycleEventArgs $args)
    {
        $rc = new \ReflectionClass('Doctrine\ORM\Event\LifecycleEventArgs');

        if ($rc->hasMethod('getObject')) {
            return $args->getObject();
        } else {
            return $args->getEntity();
        }
    }

    /**
     * Avoid calling deprecated methods if possible.
     *
     * @param LifecycleEventArgs $args
     * @return \Doctrine\Common\Persistence\ObjectManager|\Doctrine\ORM\EntityManager
     */
    protected function getOmFromLifeCycleArgs(LifecycleEventArgs $args)
    {
        $rc = new \ReflectionClass('Doctrine\ORM\Event\LifecycleEventArgs');

        if ($rc->hasMethod('getObjectManager')) {
            return $args->getObjectManager();
        } else {
            return $args->getEntityManager();
        }
    }
}
