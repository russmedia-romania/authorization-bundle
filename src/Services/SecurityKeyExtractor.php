<?php

namespace RMT\AuthorizationBundle\Services;

use Symfony\Component\Finder\Finder;

class SecurityKeyExtractor
{
    public function extract()
    {
        $classes = $this->extractFullyQualifiedClassname();

        $secured_classes = [];
        foreach ($classes as $class) {
            $interfaces = class_implements("\\".$class);
            foreach ($interfaces as $interface) {
                if(substr_count($interface, 'SecuredInterface')) {
                    $secured_classes[] = $class::getSecurityKey();
                }
            }
        }

        return $secured_classes;
    }

    private function extractFullyQualifiedClassname()
    {
        $finder = new Finder();
        $files = $finder->files()
                        ->contains('@ApiResource')
                        ->notName(basename(__FILE__))->in('src/*');

        $class_names = array();

        foreach ($files as $file) {
            $lines = file($file->getRealpath());
            $tmp = preg_grep('/^namespace /', $lines);
            if ($tmp) {
                $namespaceLine  = array_shift($tmp);
                $match          = array();
                preg_match('/^namespace (.*);$/', $namespaceLine, $match);

                if ($match) {
                    $class_names[] = trim(array_pop($match)).'\\'.($this->getClassname($file->getRealpath()));
                }
            }
        }

        return $class_names;
    }

    private function getClassname($filename)
    {
        $directoriesAndFilename = explode('/', $filename);
        $filename = array_pop($directoriesAndFilename);
        $nameAndExtension = explode('.', $filename);

        return array_shift($nameAndExtension);
    }
}