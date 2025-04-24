<?php

return [
    'core' => [
        'secret_key' => env('JWT_SECRET_KEY'),
    ],
    'access_token' => [
        'lifetime' => 5, // in minutes
    ],
    'refresh_token' => [
        'lifetime' => 30, // in minutes
    ],
];
