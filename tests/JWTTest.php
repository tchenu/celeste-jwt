<?php

namespace Feendy\JWT;

use PHPUnit\Framework\TestCase;

class JWTTest extends TestCase
{
    public function testEncode()
    {
        $secret = 'abcde';

        $token = JWT::sign($secret, [
            'demo' => 'demo'
        ]);

        $this->assertIsString($token, 'eyJhbGciOiJzaGEyNTYiLCJ0eXAiOiJKV1QifQ.eyJkZW1vIjoiZGVtbyJ9.d3c5ad706623d03f23b912eaaa0854dc5fd4c3f2158896f79af6e68f402e41c3');
    }

    public function testDecode()
    {
        $secret = 'abcde';

        $data = [
            'demo' => 'demo'
        ];

        $token = JWT::sign($secret, $data);

        $decodedData = JWT::decode($token, $secret);

        $this->assertEquals($decodedData, $data);
    }
}