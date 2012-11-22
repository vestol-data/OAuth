<?php

use GaryJones\OAuth\Token;
use GaryJones\OAuth\Util;

class TokenTest extends PHPUnit_Framework_TestCase
{
	public function testKeyAndSecretAreSet()
    {
        $token = new Token('foo', 'bar');
        $this->assertEquals('foo', $token->getKey());
        $this->assertEquals('bar', $token->getSecret());
    }

    public function testTokenString()
    {
        $token = new Token('foo', 'bar');
        $string = 'oauth_token=' . Util::urlencodeRfc3986('foo') .
            '&oauth_token_secret=' . Util::urlencodeRfc3986('bar');
        $this->assertEquals($string, $token->toString());
    }
}
