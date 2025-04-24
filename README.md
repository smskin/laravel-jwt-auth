# JWT Support Module for Laravel Projects
This module allows you to:
- generate a JWT for a user;
- authorize users via JWT (auth gateway).

## Installation
Run the following commands:
```text
composer require smskin/laravel-jwt-auth
php artisan vendor:publish --provider="SMSkin\JwtAuth\Providers\ServiceProvider"
```
Generate a random (brute-force resistant) string and store it in the `JWT_SECRET_KEY` variable in the `.env` file.

---
Add the following to the `\App\Models\User` model:
- the interface `\SMSkin\JwtAuth\Contracts\IJwtUser`;
- the trait `\SMSkin\JwtAuth\Traits\JwtTrait`.

Example after editing:
```injectablephp
class User extends Authenticatable implements IJwtUser
{
    /** @use HasFactory<\Database\Factories\UserFactory> */
    use HasFactory;
    use Notifiable;
    use JwtTrait;

    protected $table = 'users';
    ...
```
---
Add a new guard to the `auth.php` configuration file:
```injectablephp
'jwt' => [
    'driver' => 'jwt',
    'provider' => 'users',
]
```
Example after editing:
```injectablephp
...
 'guards' => [
        'web' => [
            'driver' => 'session',
            'provider' => 'users',
        ],
        'jwt' => [
            'driver' => 'jwt',
            'provider' => 'users',
        ]
    ],
...
```

## Configuration
The `jwt.php` config file contains the following variables:
- `core.secret_key` — secret key used for signing the JWT. Can be a string of any length;
- `access_token.lifetime` — access token lifetime (in minutes);
- `refresh_token.lifetime` — refresh token lifetime (in minutes).

## Usage
### How It Works
1. In exchange for login and password, the user receives 3 pieces of data:
`accessToken` — a key that allows the service to identify the user;
`expiresAt` — the timestamp when the key expires;
`refreshToken` — a key that allows the user to obtain a new access token.
2. The user sends requests to the service. The middleware `auth:jwt` is used to identify the user.
3. When the access token expires (either by time or receiving a 401 response), the user calls the refresh API method to exchange the `refreshToken` for a new `accessToken`.

### Generating an Access Token (JWT)
The `JwtTrait` includes the `generateJwt` method, which returns a `Request` instance consisting of:
- `accessToken` (string) — the access token;
- `expiresAt` (Carbon) — the expiration timestamp of the access token;
- `refreshToken` (string) — the refresh token.

### Obtaining a New Access Token via Refresh
The `IAuthService` interface provides the `refreshAccessToken` method to exchange a refresh token for a new access token.

## Example AuthController
```injectablephp
<?php

namespace App\Http\Controllers;

use App\Http\Requests\RAuthRefresh;
use App\Http\Responses\RSAccessToken;
use App\Http\Requests\RAuthLogin;
use App\Models\User;
use Auth;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Validation\ValidationException;
use SMSkin\JwtAuth\Contracts\IAuthService;
use SMSkin\JwtAuth\Exceptions\InvalidRefreshToken;

class AuthController extends Controller
{
    public function __construct(private readonly IAuthService $authService)
    {
        $this->middleware('auth:jwt')->except([
            'login',
            'refresh'
        ]);
    }

    public function check(): Response
    {
        return response()->noContent();
    }

    /**
     * @throws ValidationException
     */
    public function login(Request $request): JsonResponse
    {
        $this->validate($request, [
            'email' => [
                'required',
                'email'
            ],
            'password' => [
                'required',
                'string'
            ]
        ]);

        $check = Auth::validate([
            'email' => $request->input('email'),
            'password' => $request->input('password')
        ]);
        if (!$check) {
            throw ValidationException::withMessages([
                'password' => [
                    'Invalid password'
                ]
            ]);
        }

        /**
         * @var $user User
         */
        $user = User::where('email', $request->input('email'))->firstOrFail();
        $jwt = $user->generateJwt();
        return response()->json(new RSAccessToken(
            $jwt->accessToken,
            $jwt->expiresAt,
            $jwt->refreshToken
        ));
    }

    /**
     * @throws ValidationException
     */
    public function refresh(Request $request): JsonResponse
    {
        $this->validate($request, [
            'refreshToken' => [
                'required',
                'string'
            ]
        ]);

        try {
            $jwt = $this->authService->refreshAccessToken($request->input('refreshToken'));
        } catch (InvalidRefreshToken) {
            throw ValidationException::withMessages([
                'refreshToken' => [
                    'Invalid refresh token'
                ]
            ]);
        }
        return response()->json(new RSAccessToken(
            $jwt->accessToken,
            $jwt->expiresAt,
            $jwt->refreshToken
        ));
    }
}
```