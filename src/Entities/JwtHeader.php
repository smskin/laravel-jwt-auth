<?php

namespace SMSkin\JwtAuth\Entities;

use SMSkin\JwtAuth\Enums\AlgorithmEnum;
use SMSkin\JwtAuth\Exceptions\InvalidTokenStructure;
use SMSkin\JwtAuth\Exceptions\UnsupportedCryptAlgorithm;

class JwtHeader
{
    protected string $source;

    public function __construct(
        public readonly AlgorithmEnum $algorithm,
        public readonly string|null $kid = null,
        public readonly string|null $typ = null,
    ) {
    }

    /**
     * @throws InvalidTokenStructure
     * @throws UnsupportedCryptAlgorithm
     */
    public static function decode(string $string): self
    {
        $data = json_decode(base64_decode($string, true), true);
        if ($data === null) {
            throw new InvalidTokenStructure();
        }
        $algorithm = AlgorithmEnum::tryFrom($data['alg']);
        if ($algorithm === null) {
            throw new UnsupportedCryptAlgorithm('Unsupported algorithm: ' . $data['alg']);
        }

        return (new self(
            $algorithm,
            $data['kid'] ?? null,
            $data['typ'] ?? null
        ))->setSource($string);
    }

    public function encode(): string
    {
        $data = [
            'alg' => $this->algorithm,
        ];
        if ($this->kid !== null) {
            $data['kid'] = $this->kid;
        }
        if ($this->typ !== null) {
            $data['typ'] = $this->typ;
        }

        return rtrim(base64_encode(json_encode($data)), '=');
    }

    public function setSource(string $source): self
    {
        $this->source = $source;
        return $this;
    }

    public function getSource(): string
    {
        return $this->source;
    }
}
