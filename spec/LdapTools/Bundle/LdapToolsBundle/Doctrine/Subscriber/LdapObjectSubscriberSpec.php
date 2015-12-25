<?php
/**
 * This file is part of the LdapToolsBundle package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace spec\LdapTools\Bundle\LdapToolsBundle\Doctrine\Subscriber;

use Doctrine\Common\Annotations\Reader;
use Doctrine\Common\Persistence\ObjectManager;
use Doctrine\ORM\Event\LifecycleEventArgs;
use Doctrine\ORM\Mapping\ClassMetadata;
use LdapTools\Bundle\LdapToolsBundle\Annotation\LdapObject;
use LdapTools\Connection\LdapConnectionInterface;
use LdapTools\DomainConfiguration;
use LdapTools\Factory\LdapObjectSchemaFactory;
use LdapTools\LdapManager;
use LdapTools\Object\LdapObjectCollection;
use LdapTools\Query\LdapQuery;
use LdapTools\Query\LdapQueryBuilder;
use LdapTools\Schema\LdapObjectSchema;
use PhpSpec\ObjectBehavior;
use Prophecy\Argument;

class LdapObjectSubscriberSpec extends ObjectBehavior
{
    /**
     * @var Reader
     */
    protected $reader;

    /**
     * @var LdapManager
     */
    protected $ldap;

    /**
     * @var LifecycleEventArgs
     */
    protected $eventArgs;

    /**
     * @var object
     */
    protected $entity;

    /**
     * @var ClassMetadata
     */
    protected $metadata;

    /**
     * @var ObjectManager
     */
    protected $om;

    /**
     * @var LdapObjectSchemaFactory
     */
    protected $schemaFactory;

    /**
     * @var LdapObjectSchema
     */
    protected $schema;

    /**
     * @var LdapConnectionInterface
     */
    protected $connection;

    /**
     * @var LdapQueryBuilder
     */
    protected $qb;

    /**
     * @var LdapQuery
     */
    protected $query;

    /**
     * @var DomainConfiguration
     */
    protected $config;

    /**
     * @param \Doctrine\Common\Annotations\Reader $reader
     * @param \LdapTools\LdapManager $ldap
     * @param \Doctrine\ORM\Event\LifecycleEventArgs $eventArgs
     * @param \Doctrine\Common\Persistence\ObjectManager $om
     * @param \Doctrine\ORM\Mapping\ClassMetadata $metadata
     * @param \LdapTools\Factory\LdapObjectSchemaFactory $schemaFactory
     * @param \LdapTools\Connection\LdapConnectionInterface $connection
     * @param \LdapTools\Schema\LdapObjectSchema $schema
     * @param \LdapTools\Query\LdapQueryBuilder $qb
     * @param \LdapTools\Query\LdapQuery $query
     */
    function let($reader, $ldap, $eventArgs, $om, $metadata, $schemaFactory, $connection, $schema, $qb, $query, $entity)
    {
        $this->ldap = $ldap;
        $this->reader = $reader;
        $this->eventArgs = $eventArgs;
        $this->metadata = $metadata;
        $this->entity = $entity;
        $this->om = $om;
        $this->schemaFactory = $schemaFactory;
        $this->connection = $connection;
        $this->schema = $schema;
        $this->qb = $qb;
        $this->query = $query;

        $rc = new \ReflectionClass('Doctrine\Common\Persistence\Event\LifecycleEventArgs');

        if ($rc->hasMethod('getObjectManager')) {
            $this->eventArgs->getObjectManager()->willReturn($this->om);
            $this->eventArgs->getObject()->willReturn($this->entity);
        } else {
            $this->eventArgs->getEntityManager()->willReturn($this->om);
            $this->eventArgs->getEntity()->willReturn($this->entity);
        }

        $this->om->getClassMetadata(Argument::any())->willReturn($this->metadata);

        $this->config = new DomainConfiguration('foo.bar');
        $this->connection->getConfig()->willReturn($this->config);
        $this->ldap->getDomainContext()->willReturn('foo.bar');
        $this->ldap->getSchemaFactory()->willReturn($this->schemaFactory);
        $this->ldap->getConnection()->willReturn($this->connection);
        $this->ldap->buildLdapQuery()->willReturn($this->qb);
        $this->qb->getLdapQuery()->willReturn($this->query);

        $this->beConstructedWith($this->reader, $this->ldap);
    }

    function it_is_initializable()
    {
        $this->shouldHaveType('LdapTools\Bundle\LdapToolsBundle\Doctrine\Subscriber\LdapObjectSubscriber');
    }

    function it_should_subscribe_to_pre_persist_pre_update_and_post_load_events()
    {
        $this->getSubscribedEvents()->shouldBeEqualTo(['prePersist','preUpdate','postLoad']);
    }

    /**
     * @param \ReflectionProperty $rp1
     * @param \ReflectionProperty $rp2
     * @param \LdapTools\Object\LdapObject $ldapObject1
     * @param \LdapTools\Object\LdapObject $ldapObject2
     */
    function it_should_transform_a_ldap_object_to_its_id_value_specified_by_the_annotation($rp1, $rp2, $ldapObject1, $ldapObject2)
    {
        $this->metadata->getReflectionProperties()->shouldBeCalled()->willReturn([$rp1, $rp2]);

        $annotation1 = new LdapObject();
        $annotation2 = new LdapObject();

        $this->reader->getPropertyAnnotation($rp1, Argument::any())->shouldBeCalled()->willReturn($annotation1);
        $this->reader->getPropertyAnnotation($rp2, Argument::any())->willReturn($annotation2);

        $rp1->getValue($this->entity)->shouldBeCalled()->willReturn($ldapObject1);
        $rp2->getValue($this->entity)->shouldBeCalled()->willReturn($ldapObject2);

        // This is the default attribute value to use...
        $ldapObject1->get('guid')->shouldBeCalled()->willReturn('foo');
        $ldapObject2->get('guid')->shouldBeCalled()->willReturn('bar');

        $rp1->setValue($this->entity, 'foo')->shouldBeCalled();
        $rp2->setValue($this->entity, 'bar')->shouldBeCalled();

        // Make sure that it works with the defaults
        $this->prePersist($this->eventArgs);

        $annotation1->id = 'sid';
        $annotation2->id = 'sid';
        $ldapObject1->get('sid')->shouldBeCalled()->willReturn('foo');
        $ldapObject2->get('sid')->shouldBeCalled()->willReturn('bar');

        // Does it work when we use a different ID? ...
        $this->prePersist($this->eventArgs);
    }

    /**
     * @param \ReflectionProperty $rp
     * @param \LdapTools\Object\LdapObjectCollection $collection
     * @param \LdapTools\Object\LdapObject $ldapObject1
     * @param \LdapTools\Object\LdapObject $ldapObject2
     */
    function it_should_transform_a_ldap_object_collection_to_its_id_values_specified_by_the_annotation($rp, $collection, $ldapObject1, $ldapObject2)
    {
        $annotation = new LdapObject();
        $collection->toArray()->shouldBeCalled()->willReturn([$ldapObject1, $ldapObject2]);

        $this->metadata->getReflectionProperties()->shouldBeCalled()->willReturn([$rp]);
        $this->reader->getPropertyAnnotation($rp, Argument::any())->shouldBeCalled()->willReturn($annotation);
        $rp->getValue($this->entity)->shouldBeCalled()->willReturn($collection);

        // This is the default attribute value to use...
        $ldapObject1->get('guid')->shouldBeCalled()->willReturn('foo');
        $ldapObject2->get('guid')->shouldBeCalled()->willReturn('bar');

        $rp->setValue($this->entity, ['foo', 'bar'])->shouldBeCalled();

        $this->prePersist($this->eventArgs);
    }

    /**
     * @param \ReflectionProperty $rp
     */
    function it_should_throw_an_exception_for_unsupported_values_for_the_property($rp)
    {
        $annotation = new LdapObject();

        $this->metadata->getReflectionProperties()->shouldBeCalled()->willReturn([$rp]);
        $this->reader->getPropertyAnnotation($rp, Argument::any())->shouldBeCalled()->willReturn($annotation);
        $rp->getValue($this->entity)->shouldBeCalled()->willReturn(new \DateTime());

        $this->shouldThrow('\InvalidArgumentException')->duringPrePersist($this->eventArgs);
    }

    /**
     * @param \ReflectionProperty $rp
     */
    function it_should_load_a_single_ldap_object_from_ldap_on_post_load_based_off_annotation_data($rp)
    {
        $value = 'foo';
        $annotation = new LdapObject();
        $ldapObject = new \LdapTools\Object\LdapObject(['foo','bar'],['user'],'user','user');

        $this->metadata->getReflectionProperties()->shouldBeCalled()->willReturn([$rp]);
        $this->reader->getPropertyAnnotation($rp, Argument::any())->shouldBeCalled()->willReturn($annotation);
        $rp->getValue($this->entity)->shouldBeCalled()->willReturn($value);

        $this->schemaFactory->get($this->config->getSchemaName(), $annotation->type)->shouldBeCalled()->willReturn($this->schema);
        $this->schema->getAttributesToSelect()->shouldBeCalled()->willReturn(['foo', 'bar']);

        $this->qb->select(['foo','bar','guid'])->shouldBeCalled()->willReturn($this->qb);
        $this->qb->from($annotation->type)->shouldBeCalled()->willReturn($this->qb);
        $this->qb->where([$annotation->id => $value])->shouldBeCalled()->willReturn($this->qb);
        $this->query->getOneOrNullResult()->shouldBeCalled()->willReturn($ldapObject);

        $rp->setValue($this->entity, $ldapObject)->shouldBeCalled();

        $this->postLoad($this->eventArgs);
    }

    /**
     * @param \ReflectionProperty $rp
     */
    function it_should_load_multiple_ldap_objects_from_ldap_on_post_load_based_off_annotation_data($rp)
    {
        $value = ['foo','bar'];
        $annotation = new LdapObject();
        $annotation->collection = true;
        $collection = new LdapObjectCollection(
            new \LdapTools\Object\LdapObject(['foo','bar','guid'],['user'],'user','user'),
            new \LdapTools\Object\LdapObject(['foo','bar', 'guid'],['user'],'user','user')
        );

        $this->metadata->getReflectionProperties()->shouldBeCalled()->willReturn([$rp]);
        $this->reader->getPropertyAnnotation($rp, Argument::any())->shouldBeCalled()->willReturn($annotation);
        $rp->getValue($this->entity)->shouldBeCalled()->willReturn($value);

        $this->schemaFactory->get($this->config->getSchemaName(), $annotation->type)->shouldBeCalled()->willReturn($this->schema);
        $this->schema->getAttributesToSelect()->shouldBeCalled()->willReturn(['foo', 'bar']);

        $this->qb->select(['foo','bar','guid'])->shouldBeCalled()->willReturn($this->qb);
        $this->qb->from($annotation->type)->shouldBeCalled()->willReturn($this->qb);
        $this->qb->orWhere([$annotation->id => $value[0]])->shouldBeCalled()->willReturn($this->qb);
        $this->qb->orWhere([$annotation->id => $value[1]])->shouldBeCalled()->willReturn($this->qb);
        $this->query->getResult()->shouldBeCalled()->willReturn($collection);

        $rp->setValue($this->entity, $collection)->shouldBeCalled();

        $this->postLoad($this->eventArgs);
    }

    /**
     * @param \ReflectionProperty $rp
     */
    function it_should_select_attributes_defined_in_the_annotation_when_loading_a_ldap_object($rp)
    {
        $attributes = ['foo','guid'];
        $value = 'foo';
        $annotation = new LdapObject();
        $annotation->attributes = $attributes;
        $ldapObject = new \LdapTools\Object\LdapObject(['foo','bar'],['user'],'user','user');

        $this->metadata->getReflectionProperties()->shouldBeCalled()->willReturn([$rp]);
        $this->reader->getPropertyAnnotation($rp, Argument::any())->shouldBeCalled()->willReturn($annotation);
        $rp->getValue($this->entity)->shouldBeCalled()->willReturn($value);

        $this->schemaFactory->get($this->config->getSchemaName(), $annotation->type)->shouldNotBeCalled()->willReturn($this->schema);
        $this->schema->getAttributesToSelect()->shouldNotBeCalled();

        $this->qb->select(['foo', 'guid'])->shouldBeCalled()->willReturn($this->qb);
        $this->qb->from($annotation->type)->shouldBeCalled()->willReturn($this->qb);
        $this->qb->where([$annotation->id => $value])->shouldBeCalled()->willReturn($this->qb);
        $this->query->getOneOrNullResult()->shouldBeCalled()->willReturn($ldapObject);

        $rp->setValue($this->entity, $ldapObject)->shouldBeCalled();

        $this->postLoad($this->eventArgs);
    }

    /**
     * @param \ReflectionProperty $rp
     */
    function it_should_switch_to_the_domain_defined_in_the_annotation_when_loading_a_ldap_object($rp)
    {
        $value = 'foo';
        $annotation = new LdapObject();
        $ldapObject = new \LdapTools\Object\LdapObject(['foo','bar'],['user'],'user','user');

        $this->metadata->getReflectionProperties()->shouldBeCalled()->willReturn([$rp]);
        $this->reader->getPropertyAnnotation($rp, Argument::any())->shouldBeCalled()->willReturn($annotation);
        $rp->getValue($this->entity)->shouldBeCalled()->willReturn($value);

        $this->schemaFactory->get($this->config->getSchemaName(), $annotation->type)->shouldBeCalled()->willReturn($this->schema);
        $this->schema->getAttributesToSelect()->shouldBeCalled()->willReturn(['foo', 'bar']);

        $this->qb->select(['foo','bar','guid'])->shouldBeCalled()->willReturn($this->qb);
        $this->qb->from($annotation->type)->shouldBeCalled()->willReturn($this->qb);
        $this->qb->where([$annotation->id => $value])->shouldBeCalled()->willReturn($this->qb);
        $this->query->getOneOrNullResult()->shouldBeCalled()->willReturn($ldapObject);

        $rp->setValue($this->entity, $ldapObject)->shouldBeCalled();

        $domain = 'example.local';
        $annotation->domain = $domain;
        $this->ldap->switchDomain($domain)->shouldBeCalledTimes(1);
        $this->ldap->switchDomain('foo.bar')->shouldBeCalledTimes(1);

        $this->postLoad($this->eventArgs);
    }
}
