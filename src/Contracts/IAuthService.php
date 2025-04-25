<?php

namespace SMSkin\JwtAuth\Contracts;

use SMSkin\JwtAuth\Entities\Jwt;
use SMSkin\JwtAuth\Entities\Request;
use SMSkin\JwtAuth\Exceptions\ExpiredToken;
use SMSkin\JwtAuth\Exceptions\FutureToken;
use SMSkin\JwtAuth\Exceptions\InvalidRefreshToken;
use SMSkin\JwtAuth\Exceptions\InvalidSignature;

interface IAuthService
{
    public function generateAccessToken(IJwtUser $user, Jwt $token): Request;

    /**
     * @throws InvalidRefreshToken
     */
    public function refreshAccessToken(string $refreshToken): Request;

    /**
     * @throws FutureToken
     * @throws InvalidSignature
     * @throws ExpiredToken
     */
    public function validateAccessToken(Jwt $token);
}
