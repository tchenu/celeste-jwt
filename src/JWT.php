<?php

namespace Feendy\JWT;

use Exception;
use http\Exception\InvalidArgumentException;

class JWT
{
    const SEPARATOR = '.';

    public static $defaultAlgorithm = 'sha256';

    /**
     * Build token with given payload
     * @param string $secret
     * @param array $rawPayload
     * @return string
     */
    public static function sign(string $secret, array $rawPayload): string
    {
        if (empty($secret)) {
            // todo : change message
            throw new \InvalidArgumentException('Please give me a secret.');
        }

        $rawHeader = [
            'alg' => static::$defaultAlgorithm,
            'typ' => 'JWT'
        ];

        $encodedHeader = static::base64UrlEncode(json_encode($rawHeader));
        $encodedPayload = static::base64UrlEncode(json_encode($rawPayload));

        $rawToken = $encodedHeader . static::SEPARATOR . $encodedPayload;

        $signature = hash_hmac($rawHeader['alg'], $rawToken, $secret);

        return $rawToken . static::SEPARATOR . $signature;
    }

    /**
     * Decode token and return payload
     * @param string $token
     * @return array
     */
    public static function decode(string $token, $secret): array
    {
        if (empty($secret)) {
            // todo : change message
            throw new \InvalidArgumentException('Please give me a secret.');
        }

        $parts = explode(static::SEPARATOR, $token);

        if (count($parts) !== 3) {
            // todo : change message
            throw new \InvalidArgumentException('Too many parts');
        }

        $headers = json_decode(static::base64UrlDecode($parts[0]));
        $rawContent = $parts[0] . '.' . $parts[1];

        if (hash_hmac($headers->alg, $rawContent, $secret) !== $parts[2]) {
            throw new Exception('Invalid signature.');
        }

        return (array) json_decode(static::base64UrlDecode($parts[1]));
    }

    private static function base64UrlEncode($data)
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    private static function base64UrlDecode($data)
    {
        return base64_decode(str_pad(strtr($data, '-_', '+/'), strlen($data) % 4, '=', STR_PAD_RIGHT));
    }
}