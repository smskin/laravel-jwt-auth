<?php

namespace SMSkin\JwtAuth\Support;

use SMSkin\JwtAuth\Enums\AlgorithmEnum;
use SMSkin\JwtAuth\Exceptions\InvalidSignature;

class Crypto
{
    public function __construct(private readonly string $secretKey)
    {
    }

    public function encode(AlgorithmEnum $algorithm, string $payload): string
    {
        return hash_hmac(self::getAlgo($algorithm), $payload, $this->secretKey, false);
    }

    /**
     * @throws InvalidSignature
     */
    public function verify(AlgorithmEnum $algorithm, string $payload, string $src): void
    {
        if (hash_hmac($this->getAlgo($algorithm), $payload, $this->secretKey, false) !== $src) {
            throw new InvalidSignature();
        }
    }

    private function getAlgo(AlgorithmEnum $algorithm): string
    {
        return match ($algorithm) {
            AlgorithmEnum::HS256 => 'sha256',
            AlgorithmEnum::HS384 => 'sha384',
            AlgorithmEnum::HS512 => 'sha512'
        };
    }
}
