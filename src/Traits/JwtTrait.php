<?php

namespace SMSkin\JwtAuth\Traits;

use Illuminate\Support\Str;
use SMSkin\JwtAuth\Contracts\IAuthService;
use SMSkin\JwtAuth\Contracts\IJwtUser;
use SMSkin\JwtAuth\Entities\Jwt;
use SMSkin\JwtAuth\Entities\JwtHeader;
use SMSkin\JwtAuth\Entities\JwtPayload;
use SMSkin\JwtAuth\Entities\Request;
use SMSkin\JwtAuth\Enums\AlgorithmEnum;

trait JwtTrait
{
    public function generateJwt(): Request
    {
        $user = $this->getJwtUser();
        $expiresAt = now()->addMinutes(config('jwt.access_token.lifetime'));

        $token = new Jwt(
            new JwtHeader(AlgorithmEnum::HS256),
            new JwtPayload(
                now()->timestamp,
                $expiresAt->timestamp,
                null,
                null,
                $user->getAuthIdentifier(),
                now()->timestamp,
                $user->getAuthIdentifier() . ':' . Str::random(32),
                now()->timestamp
            )
        );

        return app(IAuthService::class)->generateAccessToken($user, $token);
    }

    private function getJwtUser(): IJwtUser
    {
        /** @noinspection PhpIncompatibleReturnTypeInspection */
        return $this;
    }
}
