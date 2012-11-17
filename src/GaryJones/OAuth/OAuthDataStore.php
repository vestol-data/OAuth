<?php
namespace GaryJones\OAuth;

interface OAuthDataStore
{
    /**
     * Lookup the client.
     *
     * @param string $client_key
     */
    public function lookupClient($client_key);

    /**
     *
     * @param type $consumer
     * @param type $token_type
     * @param type $token
     */
    public function lookupToken($consumer, $token_type, $token);

    /**
     *
     * @param type $consumer
     * @param type $token
     * @param type $nonce
     * @param type $timestamp
     */
    public function lookupNonce($consumer, $token, $nonce, $timestamp);

    /**
     * Return a new token attached to this consumer.
     *
     * @param type $consumer
     * @param type $callback
     */
    public function newRequestToken($consumer, $callback = null);

    /**
     * Return a new access token attached to this consumer for the user
     * associated with this token if the request token is authorized.
     *
     * Should also invalidate the request token.
     *
     * @param type $token
     * @param type $consumer
     * @param type $verifier
     */
    public function newAccessToken($token, $consumer, $verifier = null);
}
