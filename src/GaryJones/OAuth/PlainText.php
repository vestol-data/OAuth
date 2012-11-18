<?php
namespace GaryJones\OAuth;

/**
 * The PLAINTEXT method does not provide any security protection and SHOULD only be used
 * over a secure channel such as HTTPS. It does not use the Signature Base String.
 *   - Chapter 9.4 ("PLAINTEXT")
 */
class PlainText extends SignatureMethod
{
    public function getName()
    {
        return 'PLAINTEXT';
    }

    /**
     * oauth_signature is set to the concatenated encoded values of the Client Secret and
     * Token Secret, separated by a '&' character (ASCII code 38), even if either secret is
     * empty. The result MUST be encoded again.
     *   - Chapter 9.4.1 ("Generating Signatures")
     *
     * Please note that the second encoding MUST NOT happen in the SignatureMethod, as
     * OAuthRequest handles this!
     */
    public function buildSignature($request, $client, $token)
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
