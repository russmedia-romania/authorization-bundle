<?php

declare(strict_types=1);

namespace RMT\AuthorizationBundle\Command;

use Doctrine\ORM\EntityManagerInterface;
use RMT\AuthorizationBundle\Entity\AuthorizationSecuredEntitiesCache;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;
use RMT\AuthorizationBundle\Services\SecurityKeyExtractor;
use GuzzleHttp\Client;
use UnexpectedValueException;

class ExportSecuredEntitiesCommand extends Command
{
    protected static $defaultName = 'rmt:export-secured-entities';

    /** @var SecurityKeyExtractor **/
    private $keyExtractor;

    /** @var EntityManagerInterface **/
    private $em;

    /** @var array **/
    private $authParameters;

    /** @var string **/
    private $serviceAccountEmail;

    /** @var string **/
    private $serviceAccountPassword;

    /** @var string **/
    private $appFlavour;

    public function __construct(SecurityKeyExtractor $keyExtractor, EntityManagerInterface $em, array $authParameters, string $serviceAccountEmail, string $serviceAccountPassword, ?string $appFlavour)
    {
        $this->keyExtractor             = $keyExtractor;
        $this->em                       = $em;
        $this->authParameters           = $authParameters;
        $this->serviceAccountEmail      = $serviceAccountEmail;
        $this->serviceAccountPassword   = $serviceAccountPassword;
        $this->appFlavour               = $appFlavour;

        // you *must* call the parent constructor
        parent::__construct();
    }

    protected function configure()
    {
        $this
            ->setName(static::$defaultName)
            ->setDescription('Parse all entities, generates json payload, and send to authorization service if there is a change')
        ;
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);

        // Check if the authorization parameters are set and if the bundle is enabled
        if (empty($this->authParameters) || empty($this->authParameters['enabled']) || !$this->authParameters['enabled']) {
            $io->error('The authorization parameters are not defined or the authorization bundle is not enabled!');

            return 0;
        }

        $keys = $this->keyExtractor->extract();

        if ($keys) {
            $hash = md5(json_encode($keys));

            $cache = $this->em->getRepository(AuthorizationSecuredEntitiesCache::class)
                ->findOneBy(array(), array('id'=>'DESC'), 0, 1);

            if (!$cache || $cache->getHash() !== $hash) {
                $cache = new AuthorizationSecuredEntitiesCache;
                $cache->setHash($hash);
                $cache->setCreatedAt(new \DateTime());
                $this->em->persist($cache);
                $this->em->flush();

                $io->note('New security key were added, publish to authorization service ...');

                if ($this->export($keys)) {
                    $io->success('The keys were successfully exported to the authorization service!');
                } else {
                    $io->error('Something went wrong and the request failed!');
                }
            } else {
                $io->note('No changes found');
            }

            return 0;
        }

        $io->note('No entities found!');

        return 0;
    }

    /**
     * Method used to export the AccessRights to the authorization endpoint
     *
     * @param array $keys
     * @return boolean
     */
    private function export(array $keys): bool
    {
        if ($this->appFlavour === 'prod') {
            $baseUrl = 'http://authorization-nginx/authorization-service/api';
        } else {
            $baseUrl = 'https://' . $this->authParameters['export_service_endpoint'] . '/authorization-service/api';
        }

        $client = new Client();
        $response = $client->post($baseUrl . '/authentication_token', [
            'headers' => [
                'Accept' => 'application/json',
                'Content-Type' => 'application/json'
            ],
            'body' => json_encode([
                'username' => $this->serviceAccountEmail,
                'password' => $this->serviceAccountPassword
            ])
        ]);

        if ($response->getStatusCode() !== 200) {
            throw new UnexpectedValueException('The default service account token generation failed! Please check that you have the proper configuration.');
        }

        $response = $client->post($baseUrl . '/access_rights', [
            'headers' => [
                'Authorization' => 'Bearer ' . json_decode($response->getBody()->getContents(), true)['token'],
                'Accept'        => 'application/json',
                'Content-Type'  => 'application/json'
            ],
            'body' => json_encode([
                'data' => [
                    $this->authParameters['service_name'] => $keys
                ]
            ])
        ]);

        if ($response->getStatusCode() === 201) {
            return true;
        }

        return false;
    }
}