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
 * OAuth server.
 *
 * @package OAuth
 * @author Andy Smith
 */
class Server
{
    /**
     * Limit to which timestamp is accepted, in seconds.
     *
     * Requests older than now - this value, are rejected as possible replay attack.
     *
     * @var int
     */
    protected $timestamp_threshold = 300; // 5 minutes

    /**
     * OAuth version.
     *
     * @var string
     */
    protected $version = '1.0';

    /**
     * Supported signature methods.
     *
     * @var array
     */
    protected $signature_methods = array();

    /**
     * Data store object reference.
     *
     * @var GaryJones\OAuth\DataStore
     */
    protected $data_store;

    /**
     * Construct OAuth server instance.
     *
     * @param GaryJones\OAuth\DataStore $data_store
     */
    public function __construct(DataStore $data_store)
    {
        $this->data_store = $data_store;
    }

    /**
     * Add a supported signature method.
     *
     * @param GaryJones\OAuth\SignatureMethod $signature_method
     */
    public function addSignatureMethod(SignatureMethod $signature_method)
    {
        $this->signature_methods[$signature_method->getName()] =
            $signature_method;
    }

    // high level functions

    /**
     * Process a temporary credential (request_token) request.
     *
     * Returns the request token on success
     *
     * @param GaryJones\OAuth\Request $request
     *
     * @return GaryJones\OAuth\Token
     */
    public function fetchRequestToken(Request &$request)
    {
        $this->getVersion($request);

        $client = $this->getClient($request);

        // no token required for the initial token request
        $token = new NullToken;

        $this->checkSignature($request, $client, $token);

        // Rev A change
        $callback = $request->getParameter('oauth_callback');

        return $this->data_store->newRequestToken($client, $callback);
    }

    /**
     * Process a post-authorization token (access_token) request.
     *
     * Returns the access token on success.
     *
     * @param GaryJones\OAuth\Request $request
     *
     * @return GaryJones\OAuth\Token
     */
    public function fetchAccessToken(Request &$request)
    {
        $this->getVersion($request);

        $client = $this->getClient($request);

        // requires authorized request token
        $token = $this->getToken($request, $client, 'request');

        $this->checkSignature($request, $client, $token);

        // Rev A change
        $verifier = $request->getParameter('oauth_verifier');

        return $this->data_store->newAccessToken($token, $client, $verifier);
    }

    /**
     * Verify an api call, checks all the parameters.
     *
     * @param GaryJones\OAuth\Request $request
     *
     * @return array Client and Token
     */
    public function verifyRequest(Request &$request)
    {
        $this->getVersion($request);
        $client = $this->getClient($request);
        $token = $this->getToken($request, $client, 'access');
        $this->checkSignature($request, $client, $token);
        return array($client, $token);
    }

    // Internals from here

    /**
     * Check that version is 1.0.
     *
     * @param GaryJones\OAuth\Request $request
     *
     * @return string
     *
     * @throws GaryJones\OAuth\Exception
     */
    private function getVersion(Request &$request)
    {
        $version = $request->getParameter('oauth_version');
        if (!$version) {
            // Service Providers MUST assume the protocol version to be 1.0 if this parameter is not present.
            // Chapter 7.0 ("Accessing Protected Ressources")
            $version = '1.0';
        }
        if ($version !== $this->version) {
            throw new Exception("OAuth version '$version' not supported");
        }
        return $version;
    }

    /**
     * Get the signature method name, and if it is supported.
     *
     * @param GaryJones\OAuth\Request $request
     *
     * @return string Signature method name.
     *
     * @throws GaryJones\OAuth\Exception
     */
    private function getSignatureMethod(Request $request)
    {
        $signature_method = $request instanceof Request ? $request->getParameter('oauth_signature_method') : null;

        if (!$signature_method) {
            // According to chapter 7 ("Accessing Protected Resources") the signature-method
            // parameter is required, and we can't just fallback to PLAINTEXT
            throw new Exception('No signature method parameter. This parameter is required');
        }

        if (!in_array($signature_method, array_keys($this->signature_methods))) {
            throw new Exception(
                "Signature method '$signature_method' not supported, try one of the following: " .
                implode(", ", array_keys($this->signature_methods))
            );
        }
        return $this->signature_methods[$signature_method];
    }

    /**
     * Try to find the client for the provided request's client key.
     *
     * @param GaryJones\OAuth\Request $request
     *
     * @return GaryJones\OAuth\Client
     *
     * @throws GaryJones\OAuth\Exception
     */
    private function getClient(Request $request)
    {
        $client_key = $request instanceof Request ? $request->getParameter('oauth_consumer_key') : null;

        if (!$client_key) {
            throw new Exception('Invalid client key');
        }

        $client = $this->data_store->lookupClient($client_key);
        if (!$client) {
            throw new Exception('Invalid client');
        }

        return $client;
    }

    /**
     * Try to find the token for the provided request's token key.
     *
     * @param GaryJones\OAuth\Request $request
     * @param GaryJones\OAuth\Client  $client
     * @param string                   $token_type
     *
     * @return GaryJones\OAuth\Token
     *
     * @throws GaryJones\OAuth\Exception
     */
    private function getToken(Request $request, Client $client, $token_type = 'access')
    {
        $token_field = $request instanceof Request ? $request->getParameter('oauth_token') : null;

        $token = $this->data_store->lookupToken($client, $token_type, $token_field);
        if (!$token) {
            throw new Exception("Invalid $token_type token: $token_field");
        }
        return $token;
    }

    /**
     * All-in-one function to check the signature on a request.
     *
     * Should determine the signature method appropriately
     *
     * @param GaryJones\OAuth\Request $request
     * @param GaryJones\OAuth\Client  $client
     * @param GaryJones\OAuth\Token   $token
     *
     * @throws GaryJones\OAuth\Exception
     */
    private function checkSignature(Request $request, Client $client, Token $token)
    {
        // this should probably be in a different method
        $timestamp = $request instanceof Request ? $request->getParameter('oauth_timestamp') : null;
        $nonce = $request instanceof Request ? $request->getParameter('oauth_nonce') : null;

        $this->checkTimestamp($timestamp);
        $this->checkNonce($client, $token, $nonce, $timestamp);

        $signature_method = $this->getSignatureMethod($request);

        $signature = $request->getParameter('oauth_signature');
        $valid_sig = $signature_method->checkSignature($request, $client, $token, $signature);

        if (!$valid_sig) {
            throw new Exception('Invalid signature');
        }
    }

    /**
     * Check that the timestamp is new enough
     *
     * @param int $timestamp
     *
     * @throws GaryJones\OAuth\Exception
     */
    private function checkTimestamp($timestamp)
    {
        if (!$timestamp) {
            throw new Exception('Missing timestamp parameter. The parameter is required');
        }

        // verify that timestamp is recentish
        $now = time();
        if (abs($now - $timestamp) > $this->timestamp_threshold) {
            throw new Exception("Expired timestamp, yours $timestamp, ours $now");
        }
    }

    /**
     * Check that the nonce is not repeated
     *
     * @param GaryJones\OAuth\Client $client
     * @param GaryJones\OAuth\Token  $token
     * @param string                 $nonce
     * @param int                    $timestamp
     *
     * @throws GaryJones\OAuth\Exception
     */
    private function checkNonce(Client $client, Token $token, $nonce, $timestamp)
    {
        if (!$nonce) {
            throw new Exception('Missing nonce parameter. The parameter is required');
        }

        // verify that the nonce is uniqueish
        $found = $this->data_store->lookupNonce($client, $token, $nonce, $timestamp);
        if ($found) {
            throw new Exception('Nonce already used: ' . $nonce);
        }
    }
}
