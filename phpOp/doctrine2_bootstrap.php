<?php
require_once __DIR__ . "/libs/autoload.php";
include_once(__DIR__ . '/config.php');

use Doctrine\ORM\Tools\Setup;
use Doctrine\ORM\EntityManager;

class DbEntity {
    // Hold the entity manger instance.
    private static $instance = null;
    private $entityManager;
    private $paths = array(__DIR__ . "/Entity");
    private $isDevMode = true;

   

    // The db connection is established in the private constructor.
    private function __construct()
    {
        global $config;
        $metadataconfig = Setup::createAnnotationMetadataConfiguration($this->paths, $this->isDevMode, null, null, false);
        //$config = Setup::createXMLMetadataConfiguration(array(__DIR__."/config/xml"), $this->>isDevMode);
        $dbconfig = $config['DB'];
        $dbParams = array(
            'driver'   => 'pdo_' . $dbconfig['type'],
            'user'     => $dbconfig['user'],
            'password' => $dbconfig['password'],
            'dbname'   => $dbconfig['database'],
            'port'     => $dbconfig['port'],
            'host'     => $dbconfig['host'],
            'charset'  => 'utf8',
        );
        $this->entityManager =  EntityManager::create($dbParams, $metadataconfig);

    }

    public static function getInstance()
    {
        if(!self::$instance)
        {
            self::$instance = new DbEntity();
        }

        return self::$instance;
    }

    public function getEntityManager()
    {
        return $this->entityManager;
    }
}