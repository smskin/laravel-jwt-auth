<?php

namespace SMSkin\JwtAuth\Entities;

use SMSkin\JwtAuth\Exceptions\InvalidTokenStructure;

class JwtPayload
{
    protected string $source;

    public function __construct(
        public readonly int|null $nbf = null,
        public readonly int|null $exp = null,
        public readonly string|null $iss = null,
        public readonly string|null $aud = null,
        public readonly string|null $sub = null,
        public readonly int|null $authTime = null,
        public readonly string|null $jti = null,
        public readonly int|null $iat = null,
        public readonly array|null $amr = null,
        public readonly array|null $props = null,
    ) {
    }

    /**
     * @throws InvalidTokenStructure
     */
    public static function decode(string $string): self
    {
        $data = json_decode(base64_decode($string, true), true);
        if ($data === null) {
            throw new InvalidTokenStructure();
        }
        return (new self(
            $data['nbf'] ?? null,
            $data['exp'] ?? null,
            $data['iss'] ?? null,
            $data['aud'] ?? null,
            $data['sub'] ?? null,
            $data['auth_time'] ?? null,
            $data['jti'] ?? null,
            $data['iat'] ?? null,
            $data['amr'] ?? null,
            self::getProps($data)
        ))->setSource($string);
    }

    public function encode(): string
    {
        $data = [];
        if ($this->props !== null) {
            $data = array_merge($data, $this->props);
        }
        if ($this->nbf !== null) {
            $data['nbf'] = $this->nbf;
        }
        if ($this->exp !== null) {
            $data['exp'] = $this->exp;
        }
        if ($this->iss !== null) {
            $data['iss'] = $this->iss;
        }
        if ($this->aud !== null) {
            $data['aud'] = $this->aud;
        }
        if ($this->sub !== null) {
            $data['sub'] = $this->sub;
        }
        if ($this->authTime !== null) {
            $data['auth_time'] = $this->authTime;
        }
        if ($this->jti !== null) {
            $data['jti'] = $this->jti;
        }
        if ($this->iat !== null) {
            $data['iat'] = $this->iat;
        }
        if ($this->amr !== null) {
            $data['amr'] = $this->amr;
        }

        return rtrim(base64_encode(json_encode($data)), '=');
    }

    private static function getProps(array $props): array|null
    {
        $data = [];
        $keys = ['nbf', 'exp', 'iss', 'aud', 'sub', 'auth_time', 'jti', 'iat', 'amr'];
        foreach ($props as $key => $prop) {
            if (in_array($key, $keys)) {
                continue;
            }
            $data[$key] = $prop;
        }
        if (count($data) === 1) {
            return null;
        }
        return $data;
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
