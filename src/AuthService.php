<?php

namespace SMSkin\JwtAuth;

use Carbon\Carbon;
use Illuminate\Support\Str;
use SMSkin\JwtAuth\Contracts\IAuthService;
use SMSkin\JwtAuth\Contracts\IJwtUser;
use SMSkin\JwtAuth\Contracts\IRefreshTokenStorage;
use SMSkin\JwtAuth\Entities\Jwt;
use SMSkin\JwtAuth\Entities\Request;
use SMSkin\JwtAuth\Exceptions\ExpiredToken;
use SMSkin\JwtAuth\Exceptions\FutureToken;
use SMSkin\JwtAuth\Exceptions\InvalidRefreshToken;
use SMSkin\JwtAuth\Support\Crypto;

class AuthService implements IAuthService
{
    public function __construct(
        private readonly IRefreshTokenStorage $storage,
        private readonly Crypto $crypto
    ) {
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

    /**
     * @throws FutureToken
     * @throws Exceptions\InvalidSignature
     * @throws ExpiredToken
     */
    public function validateAccessToken(Jwt $token)
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
