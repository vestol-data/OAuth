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
 * PLAINTEXT signature method.
 *
 * The PLAINTEXT method does not provide any security protection and SHOULD only be used
 * over a secure channel such as HTTPS. It does not use the Signature Base String.
 *   - Chapter 9.4 ("PLAINTEXT")
 *
 * @package OAuth
 * @author Andy Smith
 */
class PlainText extends SignatureMethod
{
    /**
     * Return the name of the Signature Method.
     *
     * @return string
     */
    public function getName()
    {
        return 'PLAINTEXT';
    }

    /**
     * Build up the signature.
     *
     * oauth_signature is set to the concatenated encoded values of the Client Secret and
     * Token Secret, separated by a '&' character (ASCII code 38), even if either secret is
     * empty. The result MUST be encoded again.
     *   - Chapter 9.4.1 ("Generating Signatures")
     *
     * Please note that the second encoding MUST NOT happen in the SignatureMethod, as
     * OAuthRequest handles this!
     *
     * @param GaryJones\OAuth\Request $request
     * @param GaryJones\OAuth\Client  $client
     * @param GaryJones\OAuth\Token   $token
     *
     * @return string
     */
    public function buildSignature(Request $request, Client $client, Token $token = null)
    {
        $key_parts = array(
            $client->getSecret(),
            ($token) ? $token->getSecret() : ''
        );

        $key_parts = Util::urlencodeRfc3986($key_parts);
        $key = implode('&', $key_parts);
        $request->base_string = $key;

        return $key;
    }
}
