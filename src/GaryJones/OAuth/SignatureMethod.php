<?php
namespace GaryJones\OAuth;

/**
 * A class for implementing a Signature Method
 * See section 9 ("Signing Requests") in the spec
 */
abstract class SignatureMethod
{
    /**
     * Needs to return the name of the Signature Method (ie HMAC-SHA1)
     * @return string
     */
    abstract public function getName();

    /**
     * Build up the signature.
     *
     * NOTE: The output of this function MUST NOT be urlencoded.
     * the encoding is handled in OAuthRequest when the final
     * request is serialized.
     *
     * @param GaryJones\OAuth\OAuthRequest $request
     * @param GaryJones\OAuth\Client $client
     * @param GaryJones\OAuth\Token $token
     * @return string
     */
    abstract public function buildSignature($request, $client, $token);

    /**
     * Verifies that a given signature is correct.
     *
     * @param GaryJones\OAuth\OAuthRequest $request
     * @param GaryJones\OAuth\Consumer $client
     * @param GaryJones\OAuth\Token $token
     * @param string $signature
     * @return bool
     */
    public function checkSignature($request, $client, $token, $signature)
    {
        $built = $this->buildSignature($request, $client, $token);
        return $built == $signature;
    }
}
