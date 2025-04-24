<?php

namespace SMSkin\JwtAuth;

use Illuminate\Auth\GuardHelpers;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\Guard;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Http\Request;
use Illuminate\Support\Traits\Macroable;
use SMSkin\JwtAuth\Entities\Jwt;
use SMSkin\JwtAuth\Exceptions\ExpiredToken;
use SMSkin\JwtAuth\Exceptions\FutureToken;
use SMSkin\JwtAuth\Exceptions\InvalidSignature;
use SMSkin\JwtAuth\Support\Crypto;

class JwtGuard implements Guard
{
    use GuardHelpers;
    use Macroable;

    public function __construct(
        UserProvider $provider,
        private readonly Request $request,
        private readonly Crypto $crypto
    ) {
        $this->provider = $provider;
    }

    /**
     * @throws Exceptions\UnsupportedCryptAlgorithm
     * @throws Exceptions\InvalidTokenStructure
     */
    public function user(): Authenticatable|null
    {
        if ($this->hasUser()) {
            return $this->user;
        }

        $token = $this->request->bearerToken();
        if (!$token) {
            return null;
        }

        $jwt = Jwt::decode($token);
        try {
            $this->verifyToken($jwt);
        } catch (ExpiredToken|FutureToken|InvalidSignature) {
            return null;
        }

        $user = $this->provider->retrieveById($jwt->payload->sub);
        if (!$user) {
            return null;
        }

        $this->setUser($user);
        return $user;
    }

    /**
     * Validate a user's credentials.
     *
     * @param array $credentials
     * @return bool
     */
    public function validate(array $credentials = []): bool
    {
        if ($this->provider->retrieveByCredentials($credentials)) {
            return true;
        }
        return false;
    }

    /**
     * @throws InvalidSignature
     * @throws FutureToken
     * @throws ExpiredToken
     */
    private function verifyToken(Jwt $token): void
    {
        $this->crypto->verify(
            $token->header->algorithm,
            $token->header->getSource() . '.' . $token->payload->getSource(),
            $token->getCrc()
        );

        if ($token->payload->nbf !== null && time() < $token->payload->nbf) {
            throw new FutureToken();
        }

        if ($token->payload->exp !== null && time() > $token->payload->exp) {
            throw new ExpiredToken();
        }
    }
}
