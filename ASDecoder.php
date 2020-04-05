<?php

namespace AppleSignIn;

use AppleSignIn\Vendor\JWK;
use AppleSignIn\Vendor\JWT;

use Exception;

/**
 * Decode Sign In with Apple identity token, and produce an ASPayload for
 * utilizing in backend auth flows to verify validity of provided user creds.
 *
 * @package  AppleSignIn\ASDecoder
 * @author   Griffin Ledingham <gcledingham@gmail.com>
 * @license  http://opensource.org/licenses/BSD-3-Clause 3-clause BSD
 * @link     https://github.com/GriffinLedingham/php-apple-signin
 */
class ASDecoder {

    const PUBLIC_KEY_SITE = "https://appleid.apple.com/auth/keys";

    const TIME_LIMIT = 3;

    const PUBLIC_KEY = '{
        "keys": [
          {
            "kty": "RSA",
            "kid": "86D88Kf",
            "use": "sig",
            "alg": "RS256",
            "n": "iGaLqP6y-SJCCBq5Hv6pGDbG_SQ11MNjH7rWHcCFYz4hGwHC4lcSurTlV8u3avoVNM8jXevG1Iu1SY11qInqUvjJur--hghr1b56OPJu6H1iKulSxGjEIyDP6c5BdE1uwprYyr4IO9th8fOwCPygjLFrh44XEGbDIFeImwvBAGOhmMB2AD1n1KviyNsH0bEB7phQtiLk-ILjv1bORSRl8AK677-1T8isGfHKXGZ_ZGtStDe7Lu0Ihp8zoUt59kx2o9uWpROkzF56ypresiIl4WprClRCjz8x6cPZXU2qNWhu71TQvUFwvIvbkE1oYaJMb0jcOTmBRZA2QuYw-zHLwQ",
            "e": "AQAB"
          },
          {
            "kty": "RSA",
            "kid": "eXaunmL",
            "use": "sig",
            "alg": "RS256",
            "n": "4dGQ7bQK8LgILOdLsYzfZjkEAoQeVC_aqyc8GC6RX7dq_KvRAQAWPvkam8VQv4GK5T4ogklEKEvj5ISBamdDNq1n52TpxQwI2EqxSk7I9fKPKhRt4F8-2yETlYvye-2s6NeWJim0KBtOVrk0gWvEDgd6WOqJl_yt5WBISvILNyVg1qAAM8JeX6dRPosahRVDjA52G2X-Tip84wqwyRpUlq2ybzcLh3zyhCitBOebiRWDQfG26EH9lTlJhll-p_Dg8vAXxJLIJ4SNLcqgFeZe4OfHLgdzMvxXZJnPp_VgmkcpUdRotazKZumj6dBPcXI_XID4Z4Z3OM1KrZPJNdUhxw",
            "e": "AQAB"
          }
        ]
      }';

    /**
     * Parse a provided Sign In with Apple identity token.
     *
     * @param string $identityToken
     * @return object|null
     */
    public static function getAppleSignInPayload(string $identityToken) : ?object
    {
        $identityPayload = self::decodeIdentityToken($identityToken);
        return new ASPayload($identityPayload);
    }

    /**
     * Decode the Apple encoded JWT using Apple's public key for the signing.
     *
     * @param string $identityToken
     * @return object
     */
    public static function decodeIdentityToken(string $identityToken) : object {
        $publicKeyData = self::fetchPublicKey();

        $publicKey = array_column($publicKeyData,'publicKey');
        $alg = array_column($publicKeyData,'alg');

        $payload = JWT::decode($identityToken, $publicKey, [$alg]);

        return $payload;
    }

    /**
     * Fetch Apple's public key from the auth/keys REST API to use to decode
     * the Sign In JWT.
     *
     * @return array
     */
    public static function fetchPublicKey() : array {
        // 获取公钥的时候会英文网络的原因导致访问时长过长，可适当使用redis或者进行时长限制
        $publicKeys = self::fetchPublicKeyByFile();
        $decodedPublicKeys = json_decode($publicKeys, true);

        if(!isset($decodedPublicKeys['keys']) || count($decodedPublicKeys['keys']) < 1) {
            throw new Exception('Invalid key format.');
        }

        $publicKeysAll = [];
        foreach ($decodedPublicKeys['keys'] as $value) {
            $parsedKeyData = $value;
            $parsedPublicKey= JWK::parseKey($parsedKeyData);
            $publicKeyDetails = openssl_pkey_get_details($parsedPublicKey);
            
            if(!isset($publicKeyDetails['key'])) {
                continue;
            }
            $publicKeysAll[] = [
                'publicKey' => [
                    $parsedKeyData['kid'] => $publicKeyDetails['key'],
                ],
                'alg' => $parsedKeyData['alg'],
            ];
        }
        if (!$publicKeysAll) {
            throw new Exception('Invalid public key details.');
        }  
        return $publicKeysAll;
    }

    /**
     * 通过文件形式获取公钥
     * @return string
     */
    protected static function fetchPublicKeyByFile() : array {
        return file_get_contents(self::PUBLIC_KEY_SITE);
        
    } 

    /**
     * 通过缓存形式获取公钥
     * @return string
     */
    protected static function fetchPublicKeyByCache() : array {
        //TODO : Use cache
    } 

    /**
     * 通过http形式获取公钥
     * 可进行访问时长监控
     * 
     * @return string
     */
    protected static function fetchPublicKeyByHttp($param) : array {
        $gateway_url       = self::PUBLIC_KEY_SITE;
        $curl = curl_init();
        curl_setopt($curl, CURLOPT_HEADER, 0);
        curl_setopt($curl, CURLOPT_RETURNTRANSFER, 1);
        curl_setopt($curl, CURLOPT_TIMEOUT, self::TIME_LIMIT);
        curl_setopt($curl, CURLOPT_URL, $gateway_url);
        $response = curl_exec($curl);
        curl_close($curl);
        if (!$response) {
            $response = self::PUBLIC_KEY;
        }
        return $response;
    } 
}

/**
 * A class decorator for the Sign In with Apple payload produced by
 * decoding the signed JWT from a client.
 */
class ASPayload {
    protected $_instance;

    public function __construct(?object $instance) {
        if(is_null($instance)) {
            throw new Exception('ASPayload received null instance.');
        }
        $this->_instance = $instance;
    }

    public function __call($method, $args) {
        return call_user_func_array(array($this->_instance, $method), $args);
    }

    public function __get($key) {
        return $this->_instance->$key;
    }

    public function __set($key, $val) {
        return $this->_instance->$key = $val;
    }

    public function getEmail() : ?string {
        return (isset($this->_instance->email)) ? $this->_instance->email : null;
    }

    public function getUser() : ?string {
        return (isset($this->_instance->sub)) ? $this->_instance->sub : null;
    }

    public function verifyUser(string $user) : bool {
        return $user === $this->getUser();
    }
}
