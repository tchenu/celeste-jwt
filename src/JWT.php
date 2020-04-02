<?php

namespace Celeste\JWT;

use DomainException;
use Exception;
use InvalidArgumentException;
use UnexpectedValueException;

class JWT
{
    private static $hashMethods = [
      'HS256' => 'sha256'
    ];

    /**
     * Build token with given payload
     * @param array $payload
     * @param string $secret
     * @param string $algorithm
     * @return string
     * @throws Exception
     */
    public static function encode(array $payload, string $secret, string $algorithm = 'HS256'): string
    {
        // condition : if there is not secret
        if (!$secret) {
            throw new Exception('Shhh.. give me a secret');
        }

        // condition : determines if algorithm is supported or not
        if (!static::supportsAlgorithm($algorithm)) {
            throw new Exception('Algorithm not supported');
        }

        // retrieve hash method for this algorithm
        $hashMethod = static::$hashMethods[$algorithm];

        $headers = [
            'alg' => $algorithm,
            'typ' => 'JWT'
        ];

        $encodedHeaders = static::base64UrlEncode(json_encode($headers));
        $encodedPayload = static::base64UrlEncode(json_encode($payload));

        $signature = static::base64UrlEncode(
            hash_hmac($hashMethod, "{$encodedHeaders}.{$encodedPayload}", $secret, true)
        );

        return "{$encodedHeaders}.{$encodedPayload}.{$signature}";
    }

    /**
     * Decode token and return payload
     * @param string $token
     * @param string $secret
     * @param array $algorithmsAllowed
     * @return array
     * @throws InvalidSignatureException
     */
    public static function decode(string $token, string $secret, array $algorithmsAllowed): array
    {
        $parts = explode('.', $token);

        if (count($parts) !== 3) {
            throw new InvalidArgumentException('The token has more than 3 parts.');
        }

        [$encodedHeaders, $encodedPayload, $signature] = $parts;

        if (!$headers = json_decode(static::base64UrlDecode($encodedHeaders))) {
            throw new UnexpectedValueException('Can not decode headers.');
        }

        if (!$payload = json_decode(static::base64UrlDecode($encodedPayload))) {
            throw new UnexpectedValueException('Can not decode payload.');
        }

        if (!static::base64UrlDecode($signature)) {
            throw new UnexpectedValueException('Can not decode signature.');
        }

        if (!isset($headers->alg)) {
            throw new UnexpectedValueException('Alg is required.');
        }

        if (!static::supportsAlgorithm($headers->alg)) {
            throw new DomainException('Agl is not supported.');
        }

        if (!in_array($headers->alg, $algorithmsAllowed)) {
            throw new UnexpectedValueException('Alg is not allowed.');
        }

        // retrieve hash method for this algorithm
        $hashMethod = static::$hashMethods[$headers->alg];

        $localSignature = static::sign($hashMethod, $encodedHeaders, $encodedPayload, $secret);

        if (!hash_equals($localSignature, $signature)) {
            throw new InvalidSignatureException('Can not verify the signature.');
        }

        return (array) $payload;
    }

    /**
     * Return signature hashed
     * @param $hashMethod
     * @param $encodedHeaders
     * @param $encodedPayload
     * @param $secret
     * @return string
     */
    private static function sign($hashMethod, $encodedHeaders, $encodedPayload, $secret): string {
        return static::base64UrlEncode(
            hash_hmac($hashMethod, "{$encodedHeaders}.{$encodedPayload}", $secret, true)
        );
    }

    /**
     * Determine if given algorithm is supported or not
     * @param string $algorithm
     * @return bool
     */
    private static function supportsAlgorithm(string $algorithm)
    {
        return isset(static::$hashMethods[$algorithm]);
    }

    /**
     * Base64 URL encode
     * @param $data
     * @return string
     */
    private static function base64UrlEncode($data)
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    /**
     * Base64 url decode
     * @param $data
     * @return false|string
     */
    private static function base64UrlDecode($data)
    {
        return base64_decode(str_pad(strtr($data, '-_', '+/'), strlen($data) % 4, '=', STR_PAD_RIGHT));
    }
}
