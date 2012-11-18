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
     * @param type $client
     * @param type $token_type
     * @param type $token
     */
    public function lookupToken($client, $token_type, $token);

    /**
     *
     * @param type $client
     * @param type $token
     * @param type $nonce
     * @param type $timestamp
     */
    public function lookupNonce($client, $token, $nonce, $timestamp);

    /**
     * Return a new token attached to this consumer.
     *
     * @param type $client
     * @param type $callback
     */
    public function newRequestToken($client, $callback = null);

    /**
     * Return a new access token attached to this consumer for the user
     * associated with this token if the request token is authorized.
     *
     * Should also invalidate the request token.
     *
     * @param type $token
     * @param type $client
     * @param type $verifier
     */
    public function newAccessToken($token, $client, $verifier = null);
}
