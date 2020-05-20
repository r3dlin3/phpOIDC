<?php

require_once(__DIR__ . '/../libs/autoload.php');
include_once(__DIR__ . '/../config.php');

global $config;
global $twig;
$tplDir = $config['site']['views_path'];

echo "Template folder: $tplDir\n";
// iterate over all your templates
foreach (new RecursiveIteratorIterator(
                new RecursiveDirectoryIterator($tplDir),
                RecursiveIteratorIterator::LEAVES_ONLY
            ) as $file) {
    echo "Compilation of $file".PHP_EOL;
    try {
        if ($file->isFile()) {
            $twig->loadTemplate(str_replace($tplDir . '/', '', $file));
        }
    } catch (\Throwable $th) {
        echo $th.PHP_EOL;
    }
    
}

?>