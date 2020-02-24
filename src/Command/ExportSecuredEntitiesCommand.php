<?php

namespace RMT\AuthorizationBundle\Command;

use RMT\AuthorizationBundle\Entity\AuthorizationSecuredEntitiesCache;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;
use RMT\AuthorizationBundle\Services\SecurityKeyExtractor;
use Symfony\Component\DependencyInjection\ContainerInterface;

class ExportSecuredEntitiesCommand extends Command
{

    protected static $defaultName = 'authorization:export-secured-entities';

    private $keyExtractor;
    private $container;

    public function __construct(SecurityKeyExtractor $keyExtractor, ContainerInterface $container)
    {
        $this->keyExtractor = $keyExtractor;
        $this->container = $container;

        // you *must* call the parent constructor
        parent::__construct();
    }

    protected function configure()
    {
        $this
            ->setDescription('Parse all entities, generates json payload, and send to authorization service if there is a change')
        ;
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);
        $keys = $this->keyExtractor->extract();

        if ($keys) {
            $hash = md5(json_encode($keys));

            $em = $this->container->get('doctrine')->getManager();

            $cache = $em->getRepository(AuthorizationSecuredEntitiesCache::class)
                ->findOneBy(array(),array('id'=>'DESC'),0,1);

            if (!$cache || $cache->getHash() !== $hash) {
                $cache = new AuthorizationSecuredEntitiesCache;
                $cache->setHash($hash);
                $cache->setCreatedAt(new \DateTime());
                $em->persist($cache);
                $em->flush();

                $io->note("New security key were added, publish to authorization service ...");
                //send to endpoint
            } else {
                $io->note("No changes found");
            }

            return true;
        }

        $io->note("No entities found!");

        return 0;
    }
}