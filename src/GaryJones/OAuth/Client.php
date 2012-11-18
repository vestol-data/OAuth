<?php
namespace GaryJones\OAuth;

class Client
{
    protected $key;
    protected $secret;

    public function __construct($key, $secret, $callback_url = null)
    {
        $this->key = $key;
        $this->secret = $secret;
        $this->callback_url = $callback_url;
    }

    public function getKey()
    {
        return $this->key;
    }

    public function getSecret()
    {
        return $this->secret;
    }

    public function __toString()
    {
        return "OAuthClient[key=$this->key,secret=$this->secret]";
    }
}
