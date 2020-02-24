<?php

namespace RMT\AuthorizationBundle\Repository;

use RMT\AuthorizationBundle\Entity\AuthorizationSecuredEntitiesCache;
use Doctrine\Bundle\DoctrineBundle\Repository\ServiceEntityRepository;
use Doctrine\Common\Persistence\ManagerRegistry;

/**
 * @method AuthorizationSecuredEntitiesCache|null find($id, $lockMode = null, $lockVersion = null)
 * @method AuthorizationSecuredEntitiesCache|null findOneBy(array $criteria, array $orderBy = null)
 * @method AuthorizationSecuredEntitiesCache[]    findAll()
 * @method AuthorizationSecuredEntitiesCache[]    findBy(array $criteria, array $orderBy = null, $limit = null, $offset = null)
 */
class AuthorizationSecuredEntitiesCacheRepository extends ServiceEntityRepository
{
    public function __construct(ManagerRegistry $registry)
    {
        parent::__construct($registry, AuthorizationSecuredEntitiesCache::class);
    }

    // /**
    //  * @return AuthorizationSecuredEntitiesCache[] Returns an array of AuthorizationSecuredEntitiesCache objects
    //  */
    /*
    public function findByExampleField($value)
    {
        return $this->createQueryBuilder('a')
            ->andWhere('a.exampleField = :val')
            ->setParameter('val', $value)
            ->orderBy('a.id', 'ASC')
            ->setMaxResults(10)
            ->getQuery()
            ->getResult()
        ;
    }
    */

    /*
    public function findOneBySomeField($value): ?AuthorizationSecuredEntitiesCache
    {
        return $this->createQueryBuilder('a')
            ->andWhere('a.exampleField = :val')
            ->setParameter('val', $value)
            ->getQuery()
            ->getOneOrNullResult()
        ;
    }
    */
}
