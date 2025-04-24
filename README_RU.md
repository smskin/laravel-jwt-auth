# Модуль поддержки JWT для Laravel-проектов
Данный модуль позволяет:
- генерировать JWT для пользователя;
- авторизовывать пользователей по JWT (auth gateway).

## Установка
Выполните следующие команды:
```text
composer require smskin/laravel-jwt-auth
php artisan vendor:publish --provider="SMSkin\JwtAuth\Providers\ServiceProvider"
```
Сгенерируйте произвольную (стойкую к перебору) строку и запишите её в переменную `JWT_SECRET_KEY` файла `.env`.

---
В модель `\App\Models\User` добавьте:
- интерфейс `\SMSkin\JwtAuth\Contracts\IJwtUser`;
- трейд `\SMSkin\JwtAuth\Traits\JwtTrait`.

Пример файла после редактирования:
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
В файл конфигурации `auth.php` добавьте новый guard:
```injectablephp
'jwt' => [
    'driver' => 'jwt',
    'provider' => 'users',
]
```
Пример файла после редактирования:
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

## Настройка
В файле конфигурации `jwt.php` описаны следующие переменные:
- `core.secret_key` — секретный ключ для подписи JWT. Может быть строкой произвольной длины;
- `access_token.lifetime` — время жизни access token (в минутах);
- `refresh_token.lifetime` — время жизни refresh token (в минутах).

## Использование
### Принцип работы
1. Пользователь в обмен на логин и пароль получает 3 набора данных:
`accessToken` — ключ, благодаря которому сервис может идентифицировать пользователя;
`expiresAt` — метка истечения времени жизни ключа;
`refreshToken` — ключ, благодаря которому пользователь может получить новый access token.
2. Пользователь отправляет запросы в сервис. Благодаря middleware `auth:jwt` сервис идентифицирует пользователя.
3. При истечении времени жизни access token (либо по дате, либо при получении 401) пользователь обращается к API-методу refresh для обмена `refreshToken` на новый `accessToken`.

### Генерация access token (JWT)
В трейте `JwtTrait` реализован метод `generateJwt`, возвращающий экземпляр `Request`, состоящий из:
- `accessToken` (string) — access token;
- `expiresAt` (Carbon) — метка истечения времени жизни access token;
- `refreshToken` (string) — refresh token.

### Получение нового access token при refresh
В интерфейсе `IAuthService` есть метод обмена refresh token на новый access token — `refreshAccessToken`.

## Пример AuthController
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