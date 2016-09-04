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
     * @var DomainConfiguration
     */
    protected $config;

    function let(Reader $reader, LdapManager $ldap, LifecycleEventArgs $eventArgs, ObjectManager $om, ClassMetadata $metadata, LdapObjectSchemaFactory $schemaFactory, LdapConnectionInterface $connection, LdapObjectSchema $schema, LdapQueryBuilder $qb, LdapQuery $query, $entity)
    {
        $rc = new \ReflectionClass('Doctrine\Common\Persistence\Event\LifecycleEventArgs');

        if ($rc->hasMethod('getObjectManager')) {
            $eventArgs->getObjectManager()->willReturn($om);
            $eventArgs->getObject()->willReturn($entity);
        } else {
            $eventArgs->getEntityManager()->willReturn($om);
            $eventArgs->getEntity()->willReturn($entity);
        }

        $om->getClassMetadata(Argument::any())->willReturn($metadata);

        $this->config = new DomainConfiguration('foo.bar');
        $connection->getConfig()->willReturn($this->config);
        $ldap->getDomainContext()->willReturn('foo.bar');
        $ldap->getSchemaFactory()->willReturn($schemaFactory);
        $ldap->getConnection()->willReturn($connection);
        $ldap->buildLdapQuery()->willReturn($qb);
        $qb->getLdapQuery()->willReturn($query);

        $this->beConstructedWith($reader, $ldap);
    }

    function it_is_initializable()
    {
        $this->shouldHaveType('LdapTools\Bundle\LdapToolsBundle\Doctrine\Subscriber\LdapObjectSubscriber');
    }

    function it_should_subscribe_to_pre_persist_pre_update_and_post_load_events()
    {
        $this->getSubscribedEvents()->shouldBeEqualTo(['prePersist','preUpdate','postLoad']);
    }

    function it_should_transform_a_ldap_object_to_its_id_value_specified_by_the_annotation($entity, $eventArgs, $reader, $metadata, \ReflectionProperty $rp1, \ReflectionProperty $rp2, \LdapTools\Object\LdapObject $ldapObject1, \LdapTools\Object\LdapObject $ldapObject2)
    {
        $metadata->getReflectionProperties()->shouldBeCalled()->willReturn([$rp1, $rp2]);

        $annotation1 = new LdapObject();
        $annotation2 = new LdapObject();

        $reader->getPropertyAnnotation($rp1, Argument::any())->shouldBeCalled()->willReturn($annotation1);
        $reader->getPropertyAnnotation($rp2, Argument::any())->willReturn($annotation2);

        $rp1->getValue($entity)->shouldBeCalled()->willReturn($ldapObject1);
        $rp2->getValue($entity)->shouldBeCalled()->willReturn($ldapObject2);

        // This is the default attribute value to use...
        $ldapObject1->get('guid')->shouldBeCalled()->willReturn('foo');
        $ldapObject2->get('guid')->shouldBeCalled()->willReturn('bar');

        $rp1->setValue($entity, 'foo')->shouldBeCalled();
        $rp2->setValue($entity, 'bar')->shouldBeCalled();

        // Make sure that it works with the defaults
        $this->prePersist($eventArgs);

        $annotation1->id = 'sid';
        $annotation2->id = 'sid';
        $ldapObject1->get('sid')->shouldBeCalled()->willReturn('foo');
        $ldapObject2->get('sid')->shouldBeCalled()->willReturn('bar');

        // Does it work when we use a different ID? ...
        $this->prePersist($eventArgs);
    }

    function it_should_transform_a_ldap_object_collection_to_its_id_values_specified_by_the_annotation($entity, $eventArgs, $reader, $metadata, \ReflectionProperty $rp, LdapObjectCollection $collection, \LdapTools\Object\LdapObject $ldapObject1, \LdapTools\Object\LdapObject $ldapObject2)
    {
        $annotation = new LdapObject();
        $collection->toArray()->shouldBeCalled()->willReturn([$ldapObject1, $ldapObject2]);

        $metadata->getReflectionProperties()->shouldBeCalled()->willReturn([$rp]);
        $reader->getPropertyAnnotation($rp, Argument::any())->shouldBeCalled()->willReturn($annotation);
        $rp->getValue($entity)->shouldBeCalled()->willReturn($collection);

        // This is the default attribute value to use...
        $ldapObject1->get('guid')->shouldBeCalled()->willReturn('foo');
        $ldapObject2->get('guid')->shouldBeCalled()->willReturn('bar');

        $rp->setValue($entity, ['foo', 'bar'])->shouldBeCalled();

        $this->prePersist($eventArgs);
    }

    function it_should_throw_an_exception_for_unsupported_values_for_the_property($entity, $eventArgs, $metadata, $reader, \ReflectionProperty $rp)
    {
        $annotation = new LdapObject();

        $metadata->getReflectionProperties()->shouldBeCalled()->willReturn([$rp]);
        $reader->getPropertyAnnotation($rp, Argument::any())->shouldBeCalled()->willReturn($annotation);
        $rp->getValue($entity)->shouldBeCalled()->willReturn(new \DateTime());

        $this->shouldThrow('\InvalidArgumentException')->duringPrePersist($eventArgs);
    }

    function it_should_load_a_single_ldap_object_from_ldap_on_post_load_based_off_annotation_data($eventArgs, $query, $qb, $schemaFactory, $schema, $entity, $metadata, $reader, \ReflectionProperty $rp)
    {
        $value = 'foo';
        $annotation = new LdapObject();
        $ldapObject = new \LdapTools\Object\LdapObject(['foo','bar'],['user'],'user','user');

        $metadata->getReflectionProperties()->shouldBeCalled()->willReturn([$rp]);
        $reader->getPropertyAnnotation($rp, Argument::any())->shouldBeCalled()->willReturn($annotation);
        $rp->getValue($entity)->shouldBeCalled()->willReturn($value);

        $schemaFactory->get($this->config->getSchemaName(), $annotation->type)->shouldBeCalled()->willReturn($schema);
        $schema->getAttributesToSelect()->shouldBeCalled()->willReturn(['foo', 'bar']);

        $qb->select(['foo','bar','guid'])->shouldBeCalled()->willReturn($qb);
        $qb->from($annotation->type)->shouldBeCalled()->willReturn($qb);
        $qb->where([$annotation->id => $value])->shouldBeCalled()->willReturn($qb);
        $query->getOneOrNullResult()->shouldBeCalled()->willReturn($ldapObject);

        $rp->setValue($entity, $ldapObject)->shouldBeCalled();

        $this->postLoad($eventArgs);
    }

    function it_should_load_multiple_ldap_objects_from_ldap_on_post_load_based_off_annotation_data($schemaFactory, $eventArgs, $schema, $qb, $query, $metadata, $reader, $entity, \ReflectionProperty $rp)
    {
        $value = ['foo','bar'];
        $annotation = new LdapObject();
        $annotation->collection = true;
        $collection = new LdapObjectCollection(
            new \LdapTools\Object\LdapObject(['foo','bar','guid'],['user'],'user','user'),
            new \LdapTools\Object\LdapObject(['foo','bar', 'guid'],['user'],'user','user')
        );

        $metadata->getReflectionProperties()->shouldBeCalled()->willReturn([$rp]);
        $reader->getPropertyAnnotation($rp, Argument::any())->shouldBeCalled()->willReturn($annotation);
        $rp->getValue($entity)->shouldBeCalled()->willReturn($value);

        $schemaFactory->get($this->config->getSchemaName(), $annotation->type)->shouldBeCalled()->willReturn($schema);
        $schema->getAttributesToSelect()->shouldBeCalled()->willReturn(['foo', 'bar']);

        $qb->select(['foo','bar','guid'])->shouldBeCalled()->willReturn($qb);
        $qb->from($annotation->type)->shouldBeCalled()->willReturn($qb);
        $qb->orWhere([$annotation->id => $value[0]])->shouldBeCalled()->willReturn($qb);
        $qb->orWhere([$annotation->id => $value[1]])->shouldBeCalled()->willReturn($qb);
        $query->getResult()->shouldBeCalled()->willReturn($collection);

        $rp->setValue($entity, $collection)->shouldBeCalled();

        $this->postLoad($eventArgs);
    }

    function it_should_select_attributes_defined_in_the_annotation_when_loading_a_ldap_object($schema, $schemaFactory, $reader, $metadata, $entity, $qb, $query, $eventArgs, \ReflectionProperty $rp)
    {
        $attributes = ['foo','guid'];
        $value = 'foo';
        $annotation = new LdapObject();
        $annotation->attributes = $attributes;
        $ldapObject = new \LdapTools\Object\LdapObject(['foo','bar'],['user'],'user','user');

        $metadata->getReflectionProperties()->shouldBeCalled()->willReturn([$rp]);
        $reader->getPropertyAnnotation($rp, Argument::any())->shouldBeCalled()->willReturn($annotation);
        $rp->getValue($entity)->shouldBeCalled()->willReturn($value);

        $schemaFactory->get($this->config->getSchemaName(), $annotation->type)->shouldNotBeCalled()->willReturn($schema);
        $schema->getAttributesToSelect()->shouldNotBeCalled();

        $qb->select(['foo', 'guid'])->shouldBeCalled()->willReturn($qb);
        $qb->from($annotation->type)->shouldBeCalled()->willReturn($qb);
        $qb->where([$annotation->id => $value])->shouldBeCalled()->willReturn($qb);
        $query->getOneOrNullResult()->shouldBeCalled()->willReturn($ldapObject);

        $rp->setValue($entity, $ldapObject)->shouldBeCalled();

        $this->postLoad($eventArgs);
    }

    function it_should_switch_to_the_domain_defined_in_the_annotation_when_loading_a_ldap_object($eventArgs, $schema, $ldap, $qb, $query, $entity, $schemaFactory, $reader, $metadata, \ReflectionProperty $rp)
    {
        $value = 'foo';
        $annotation = new LdapObject();
        $ldapObject = new \LdapTools\Object\LdapObject(['foo','bar'],['user'],'user','user');

        $metadata->getReflectionProperties()->shouldBeCalled()->willReturn([$rp]);
        $reader->getPropertyAnnotation($rp, Argument::any())->shouldBeCalled()->willReturn($annotation);
        $rp->getValue($entity)->shouldBeCalled()->willReturn($value);

        $schemaFactory->get($this->config->getSchemaName(), $annotation->type)->shouldBeCalled()->willReturn($schema);
        $schema->getAttributesToSelect()->shouldBeCalled()->willReturn(['foo', 'bar']);

        $qb->select(['foo','bar','guid'])->shouldBeCalled()->willReturn($qb);
        $qb->from($annotation->type)->shouldBeCalled()->willReturn($qb);
        $qb->where([$annotation->id => $value])->shouldBeCalled()->willReturn($qb);
        $query->getOneOrNullResult()->shouldBeCalled()->willReturn($ldapObject);

        $rp->setValue($entity, $ldapObject)->shouldBeCalled();

        $domain = 'example.local';
        $annotation->domain = $domain;
        $ldap->switchDomain($domain)->shouldBeCalledTimes(1);
        $ldap->switchDomain('foo.bar')->shouldBeCalledTimes(1);

        $this->postLoad($eventArgs);
    }
}
