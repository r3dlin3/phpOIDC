<?php
require_once __DIR__ . "/libs/autoload.php";
require_once  "dbconf.php";

use Doctrine\ORM\Tools\Setup;
use Doctrine\ORM\EntityManager;


// the connection configuration




class DbEntity {
    // Hold the entity manger instance.
    private static $instance = null;
    private $entityManager;
    private $paths = array(__DIR__ . "/Entity");
    private $isDevMode = true;

    private $dbParams = array(
        'driver'   => 'pdo_mysql',
        'user'     => DB_USER,
        'password' => DB_PASSWORD,
        'dbname'   => DB_DATABASE,
        'port' => DB_PORT,
        'host'     => DB_HOST,
        'charset'  => 'utf8',
    );

//    private $dbParams = array(
//        'driver'   => 'pdo_mysql',
//        'user'     => 'phpoidc',
//        'password' => 'test',
//        'dbname'   => 'phpoidc_02',
//        'charset'  => 'utf8'
//        //    'port' => 330,
//        //    'host'     => 'localhost'
//    );

    private $dbTestParams1 = array(
        'driver'   => 'pdo_sqlite',
        'user'     => 'phpoidc',
        'password' => 'test',
        'memory'   => false,
        'path'     =>  __DIR__ . '/phpoidc.sqlite'
        //    'port' => 330,
        //    'host'     => 'localhost'
    );

    private $dbTestParams = array(
        'driver'   => 'pdo_mysql',
        'user'     => 'phpoidc',
        'password' => 'test',
        'dbname'   => 'phpoidc_02',
        'charset'  => 'utf8'

        //    'port' => 330,
        //    'host'     => 'localhost'
    );


    // The db connection is established in the private constructor.
    private function __construct()
    {
        $config = Setup::createAnnotationMetadataConfiguration($this->paths, $this->isDevMode, null, null, false);
        //$config = Setup::createXMLMetadataConfiguration(array(__DIR__."/config/xml"), $this->>isDevMode);

        $this->entityManager =  EntityManager::create($this->dbParams, $config);

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


//use Doctrine\ORM\Tools\Setup;
//use Doctrine\ORM\EntityManager;
//
//require_once "libs/autoload.php";
//
//// Create a simple "default" Doctrine ORM configuration for Annotations
//$isDevMode = true;
//$config = Setup::createAnnotationMetadataConfiguration(array(__DIR__."/src"), $isDevMode);
//// or if you prefer yaml or XML
////$config = Setup::createXMLMetadataConfiguration(array(__DIR__."/config/xml"), $isDevMode);
////$config = Setup::createYAMLMetadataConfiguration(array(__DIR__."/config/yaml"), $isDevMode);
//
//// database configuration parameters
//$conn = array(
//    'driver'   => 'pdo_mysql',
//    'user'     => 'phpoidc',
//    'password' => 'test',
//    'dbname'   => 'phpOidc_01',
//);
//
//// obtaining the entity manager
//$entityManager = EntityManager::create($conn, $config);