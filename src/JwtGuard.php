<?php

namespace SMSkin\JwtAuth;

use Illuminate\Auth\GuardHelpers;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\Guard;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Http\Request;
use Illuminate\Support\Traits\Macroable;
use SMSkin\JwtAuth\Contracts\IAuthService;
use SMSkin\JwtAuth\Entities\Jwt;
use SMSkin\JwtAuth\Exceptions\ExpiredToken;
use SMSkin\JwtAuth\Exceptions\FutureToken;
use SMSkin\JwtAuth\Exceptions\InvalidSignature;

class JwtGuard implements Guard
{
    use GuardHelpers;
    use Macroable;

    public function __construct(
        UserProvider $provider,
        private readonly Request $request,
        private readonly IAuthService $authService
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
            $this->authService->validateAccessToken($jwt);
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
}
