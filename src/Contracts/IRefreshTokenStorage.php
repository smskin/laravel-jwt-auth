<?php

namespace SMSkin\JwtAuth\Contracts;

interface IRefreshTokenStorage
{
    public function getUser(string $refreshToken): IJwtUser|null;

    public function create(IJwtUser $user, string $refreshToken): void;

    public function delete(IJwtUser $user, string $refreshToken): void;
}
