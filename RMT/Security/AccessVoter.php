<?php

namespace RMT\AuthorizationBundle\Security;

use ApiPlatform\Core\Bridge\Doctrine\MongoDbOdm\Paginator as MongoDbPaginator;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Authorization\Voter\Voter;
use ApiPlatform\Core\Bridge\Doctrine\Orm\Paginator as OrmPaginator;
use ApiPlatform\Core\Bridge\Elasticsearch\DataProvider\Paginator as DataProviderPaginator;
use Symfony\Component\DependencyInjection\Exception\ParameterNotFoundException;
use Predis\Client;
use Predis\Response\ServerException;

class AccessVoter extends Voter
{
    const SECURITY_KEY_METHOD   = 'getSecurityKey';
    const SUPPORTED_ATTRIBUTES  = ['WRITE' => 0, 'READ' => 0, 'DELETE' => 0];
    const ROLE_SUPER_ADMIN      = 'ROLE_SUPER_ADMIN';
    const ROLE_SERVICE_ACCOUNT  = 'ROLE_SERVICE_ACCOUNT';

    private $container;
    protected $authParameters;

    public function __construct(ContainerInterface $container)
    {
        $this->container = $container;
        $this->authParameters = $this->container->hasParameter('authorization') ? $this->container->getParameter('authorization') : null;
    }

    public function vote(TokenInterface $token, $subject, array $attributes)
    {
        $vote = self::ACCESS_ABSTAIN;

        if (isset($this->authParameters['enabled']) && $this->authParameters['enabled'] !== true) {
            return self::ACCESS_GRANTED;
        }

        $roles = $token->getUser()->getRoles();

        foreach ($roles as $role) {
            if ($role === self::ROLE_SUPER_ADMIN || $role === self::ROLE_SERVICE_ACCOUNT) {
                return self::ACCESS_GRANTED;
            }
        }

        if ($subject instanceof OrmPaginator || $subject instanceof DataProviderPaginator || $subject instanceof MongoDbPaginator) {
            $iterator = $subject->getIterator();

            if ($iterator && isset($iterator[0])) {
                if (!method_exists($iterator[0], self::SECURITY_KEY_METHOD)) {
                    return self::ACCESS_DENIED;
                }

                $subject = $iterator[0];
            }
        }

        foreach ($attributes as $attribute) {
            if (!$this->supports($attribute, $subject)) {
                continue;
            }

            // as soon as at least one attribute is supported, default is to deny access
            $vote = self::ACCESS_DENIED;

            if ($this->voteOnAttribute($attribute, $subject, $roles)) {
                // grant access as soon as at least one attribute returns a positive response
                return self::ACCESS_GRANTED;
            }
        }

        return $vote;
    }

    protected function supports($attribute, $subject)
    {
        if (!isset(self::SUPPORTED_ATTRIBUTES[$attribute]) && is_object($subject) && !method_exists($subject, self::SECURITY_KEY_METHOD)) {
            return false;
        }

        return true;
    }

    protected function voteOnAttribute($attribute, $subject, $roles)
    {
        if (isset($this->authParameters['redis_url']) && isset($this->authParameters['service_name']) && $subject::getSecurityKey()) {
            try {
                $redisClient = new Client($this->container->getParameter('authorization')['redis_url']);
                $redisClient->ping();
            } catch (\Exception $e) {
                throw new ServerException('Redis instance is not responding! Check if the server is running.');
            }

            foreach ($roles as $role) {
                // todo remove the set method for redis ( only used for testing purposes )
                $redisClient->set('media' . '-' . $subject::getSecurityKey() . '-' . $role, serialize(['DELETE' , 'WRITE']));
                $roleAccess = unserialize($redisClient->get($this->authParameters['service_name'] . '-' . $subject::getSecurityKey() . '-' . $role));

                if ($roleAccess && in_array($attribute, $roleAccess)) {
                    return true;
                }
            }

            return false;
        }

        throw new ParameterNotFoundException('The authorization configuration parameters are missing!');
    }

}