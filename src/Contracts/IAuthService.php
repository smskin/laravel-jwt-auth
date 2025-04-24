<?php

namespace SMSkin\JwtAuth\Contracts;

use SMSkin\JwtAuth\Entities\Jwt;
use SMSkin\JwtAuth\Entities\Request;
use SMSkin\JwtAuth\Exceptions\InvalidRefreshToken;

interface IAuthService
{
    public function generateAccessToken(IJwtUser $user, Jwt $token): Request;

    /**
     * @throws InvalidRefreshToken
     */
    public function refreshAccessToken(string $refreshToken): Request;
}
