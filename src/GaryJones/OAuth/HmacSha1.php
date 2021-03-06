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
 * The HMAC-SHA1 signature method.
 *
 * The HMAC-SHA1 signature method. uses the HMAC-SHA1 signature algorithm as defined in [RFC2104]
 * where the Signature Base String is the text and the key is the concatenated values (each first
 * encoded per Parameter Encoding) of the Consumer Secret and Token Secret, separated by an '&'
 * character (ASCII code 38) even if empty.
 *   - Chapter 9.2 ("HMAC-SHA1")
 *
 * @package OAuth
 * @author Andy Smith
 */
class HmacSha1 extends SignatureMethod
{
    /**
     * Return the name of the Signature Method.
     *
     * @return string
     */
    public function getName()
    {
        return 'HMAC-SHA1';
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
        $base_string = $request->getSignatureBaseString();
        $key = $this->getSignatureKey($client, $token);

        return base64_encode(hash_hmac('sha1', $base_string, $key, true));
    }
}
