<?php

namespace SMSkin\JwtAuth\Enums;

enum AlgorithmEnum: string
{
    case HS256 = 'HS256';
    case HS384 = 'HS384';
    case HS512 = 'HS512';
}
