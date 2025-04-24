<?php

namespace SMSkin\JwtAuth\Entities;

use Carbon\Carbon;

class Request
{
    public function __construct(
        public readonly string $accessToken,
        public readonly Carbon|null $expiresAt,
        public readonly string $refreshToken
    ) {
    }
}
