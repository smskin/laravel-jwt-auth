<?php

namespace SMSkin\JwtAuth\Support;

use Illuminate\Support\Facades\Cache;
use SMSkin\JwtAuth\Contracts\IJwtUser;
use SMSkin\JwtAuth\Contracts\IRefreshTokenStorage;

class RefreshTokenStorage implements IRefreshTokenStorage
{
    public function getUser(string $refreshToken): IJwtUser|null
    {
        $id = Cache::get($this->getCacheKey($refreshToken));
        $model = config('auth.providers.users.model');
        return $model::query()->find($id);
    }

    public function create(IJwtUser $user, string $refreshToken): void
    {
        Cache::put($this->getCacheKey($refreshToken), $user->getAuthIdentifier(), now()->addMonth());
    }

    public function delete(IJwtUser $user, string $refreshToken): void
    {
        Cache::forget($this->getCacheKey($refreshToken));
    }

    private function getCacheKey(string $refreshToken): string
    {
        return 'jwt_rt_' . md5($refreshToken);
    }
}
