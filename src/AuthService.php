<?php

namespace SMSkin\JwtAuth;

use Carbon\Carbon;
use Illuminate\Support\Str;
use SMSkin\JwtAuth\Contracts\IAuthService;
use SMSkin\JwtAuth\Contracts\IJwtUser;
use SMSkin\JwtAuth\Contracts\IRefreshTokenStorage;
use SMSkin\JwtAuth\Entities\Jwt;
use SMSkin\JwtAuth\Entities\Request;
use SMSkin\JwtAuth\Exceptions\InvalidRefreshToken;

class AuthService implements IAuthService
{
    public function __construct(private readonly IRefreshTokenStorage $storage)
    {
    }

    public function generateAccessToken(IJwtUser $user, Jwt $token): Request
    {
        $refreshToken = Str::random(128);
        $this->storage->create($user, $refreshToken);

        return new Request(
            $token->encode(),
            $token->payload->exp ? Carbon::createFromTimestamp($token->payload->exp) : null,
            $refreshToken
        );
    }

    /**
     * @throws InvalidRefreshToken
     */
    public function refreshAccessToken(string $refreshToken): Request
    {
        $user = $this->storage->getUser($refreshToken);
        if (!$user) {
            throw new InvalidRefreshToken();
        }
        $this->storage->delete($user, $refreshToken);
        return $user->generateJwt();
    }
}
