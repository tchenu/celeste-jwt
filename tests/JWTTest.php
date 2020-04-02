<?php

namespace Feendy\JWT;

use PHPUnit\Framework\TestCase;

class JWTTest extends TestCase
{
    public function testEncode()
    {
        $secret = 'abcde';

        $token = JWT::encode([
            'demo' => 'demo'
        ], $secret);

        $this->assertEquals($token, 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJkZW1vIjoiZGVtbyJ9.JPnoEfCf31_Ghl7rL6TZqoHFXnQFrfyVsmjNOZCEboE');
    }

    public function testDecode()
    {
        $secret = 'abcde';

        $payload = [
            'demo' => 'demo'
        ];

        $token = JWT::encode($payload, $secret);

        $data = JWT::decode($token, $secret, ['HS256']);

        $this->assertEquals($data, $payload);
    }
}