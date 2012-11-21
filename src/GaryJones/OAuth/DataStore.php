<?php
/**
 * OAuth
 *
 * @package OAuth
 * @author Andy Smith
 * @author Gary Jones <gary@garyjones.co.uk>
 * @license https://raw.github.com/GaryJones/OAuth/master/LICENSE MIT
 * @link https://github.com/GaryJones/OAuth
 */

namespace GaryJones\OAuth;

/**
 * The actual implementation of validating and assigning tokens is left up to
 * the system using this library.
 *
 * @package OAuth
 * @author Gary Jones <gary@garyjones.co.uk>
 */
interface DataStore
{
    /**
     * Validate the client.
     *
     * @param string $client_key
     */
    public function lookupClient($client_key);

    /**
     * Validate a token.
     *
     * @param GaryJones\OAuth\Client $client
     * @param GaryJones\OAuth\Token  $token
     * @param string                 $token_type Request or access token
     */
    public function lookupToken(Client $client, Token $token, $token_type);

    /**
     * Validate that a nonce has not been used with the same timestamp before.
     *
     * @param GaryJones\OAuth\Client $client
     * @param GaryJones\OAuth\Token  $token
     * @param string                 $nonce
     * @param int                    $timestamp
     */
    public function lookupNonce(Client $client, Token $token, $nonce, $timestamp);

    /**
     * Return a new token attached to this client.
     *
     * @param GaryJones\OAuth\Client $client
     * @param string                 $callback URI to store as the post-authorization callback.
     */
    public function newRequestToken(Client $client, $callback = null);

    /**
     * Return a new access token attached to this consumer for the user
     * associated with this token if the request token is authorized.
     *
     * Should also invalidate the request token.
     *
     * @param GaryJones\OAuth\Client $client
     * @param GaryJones\OAuth\Token  $token
     * @param string                 $verifier
     */
    public function newAccessToken(Client $client, Token $token, $verifier = null);
}
