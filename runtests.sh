#!/bin/sh
vendor/phpunit/phpunit/phpunit.php --stderr --bootstrap tests/bootstrap.php tests/tests.php
