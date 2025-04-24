<?php

namespace SMSkin\JwtAuth\Contracts;

use SMSkin\JwtAuth\Entities\Request;

interface IJwtUser
{
    public function getAuthIdentifier();

    public function generateJwt(): Request;
}
