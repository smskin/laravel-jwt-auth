<?php

return [
    'core' => [
        'secret_key' => env('JWT_SECRET_KEY'),
    ],
    'access_token' => [
        'lifetime' => 5, // in minutes
    ],
];
