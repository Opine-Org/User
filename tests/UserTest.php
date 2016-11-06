<?php
namespace Opine\Container;

use PHPUnit_Framework_TestCase;
use Opine\Container\Service as Container;
use Opine\Config\Service as Config;

class UserTest extends PHPUnit_Framework_TestCase
{
    private $container;

    public function setup()
    {
        $root = __DIR__.'/../public';
        $config = new Config($root);
        $config->cacheSet();
        $this->container = Container::instance($root, $config, $root.'/../config/containers/test-container.yml');
    }
}
