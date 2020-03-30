<?php

namespace Feendy\JWT;

use Exception;
use InvalidArgumentException;

class JWT
{

    /**
     * Build token with given payload
     * @param array $rawPayload
     * @param string $secret
     * @return string
     */
    public static function encode(array $rawPayload, string $secret): string
    {
        $rawHeader = [
            'alg' => 'sha256',
            'typ' => 'JWT'
        ];

        // json_encode + base64Url
        $encodedHeader = static::rawEncode($rawHeader);
        $encodedPayload = static::rawEncode($rawPayload);

        $signature = hash_hmac($rawHeader['alg'], "{$encodedHeader}.{$encodedPayload}", $secret);

        // token: ${header}.${payload}.${signature}
        return "{$encodedHeader}.{$encodedPayload}.{$signature}";
    }

    /**
     * Decode token and return payload
     * @param string $token
     * @param string $secret
     * @return array
     * @throws Exception
     * @todo : use explode, add more functions
     */
    public static function decode(string $token, string $secret): array
    {
        $parts = explode('.', $token);

        if (count($parts) !== 3) {
            throw new InvalidArgumentException('The token has more than 3 parts.');
        }

        [$encodedHeaders, $encodedPayload, $signature] = $parts;

        $headers = static::rawDecode($encodedHeaders);

        if (hash_hmac($headers->alg, "{$encodedHeaders}.{$encodedPayload}", $secret) !== $signature) {
            throw new Exception('Invalid signature.');
        }

        return (array) static::rawDecode($encodedPayload);
    }

    private static function rawEncode($data)
    {
        return static::base64UrlEncode(json_encode($data));
    }

    private static function base64UrlEncode($data)
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    private static function rawDecode($data)
    {
        return json_decode(static::base64UrlDecode($data));
    }

    private static function base64UrlDecode($data)
    {
        return base64_decode(str_pad(strtr($data, '-_', '+/'), strlen($data) % 4, '=', STR_PAD_RIGHT));
    }
}
