<?php

namespace Accolon\Jwt;

use Accolon\Jwt\Exceptions\InvalidTokenException;

final class Jwt
{
    private static $algs = [
        'HS256' => array('hash_hmac', 'SHA256'),
        'HS384' => array('hash_hmac', 'SHA384'),
        'HS512' => array('hash_hmac', 'SHA512'),
        'RS256' => array('openssl', 'SHA256'),
        'RS384' => array('openssl', 'SHA384'),
        'RS512' => array('openssl', 'SHA512'),
    ];

    public static function encode($payload, string $key, string $algo = 'HS256'): string
    {
        $header = self::base64UrlEncode(json_encode([
            'alg' => $algo,
            'typ' => 'JWT'
        ]));

        $payload = self::base64UrlEncode(json_encode($payload));

        $signature = self::base64UrlEncode(static::sign($algo, "{$header}.{$payload}", $key));

        return "{$header}.{$payload}.{$signature}";
    }

    public static function decode(string $token, string $key, $algo = 'HS256')
    {
        $segments = explode(".", $token);

        if (count($segments) !== 3) {
            throw new InvalidTokenException("Jwt token must have 3 segments");
        }

        [$header64, $payload64, $signature64] = $segments;

        $header = json_decode(self::base64UrlDecode($header64));

        if ($header === null) {
            throw new \UnexpectedValueException('Invalid header');
        }

        $payload = json_decode(self::base64UrlDecode($payload64), true);

        if ($payload === null) {
            throw new \UnexpectedValueException('Invalid payload');
        }

        $sig = self::base64UrlDecode($signature64);

        if ($sig === false) {
            throw new \UnexpectedValueException('Invalid signature');
        }

        if (!self::verify("{$header64}.{$payload64}", $sig, $key, $header->alg)) {
            throw new \UnexpectedValueException('Signature failed');
        }

        return $payload;
    }

    public static function verify($payload, $signature, $key, $algo): bool
    {
        [$function, $alg] = self::$algs[$algo];

        if ($function === 'openssl') {
            return openssl_verify($payload, $signature, $key, $alg);
        }

        if ($function === 'hash_hmac') {
            $hash = hash_hmac($alg, $payload, $key, true);

            return hash_equals($signature, $hash);
        }
    }

    private static function sign(string $algo, string $data, string $key)
    {
        [$function, $alg] = static::$algs[$algo];

        if ($function === 'hash_hmac') {
            return hash_hmac($alg, $data, $key, true);
        }

        if ($function === 'openssl') {
            $signature = '';
            openssl_sign($data, $signature, $key, $alg);
            return $signature;
        }
    }

    private static function base64UrlEncode(string $data): string
    {
        return str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($data));
    }

    private static function base64UrlDecode(string $data)
    {
        return base64_decode(str_pad(strtr($data, '-_', '+/'), strlen($data) % 4, '=', STR_PAD_RIGHT));
    }
}
