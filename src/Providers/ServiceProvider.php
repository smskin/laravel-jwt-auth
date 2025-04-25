<?php

namespace SMSkin\JwtAuth\Providers;

use Illuminate\Contracts\Foundation\Application;
use Illuminate\Support\Facades\Auth;
use SMSkin\JwtAuth\AuthService;
use SMSkin\JwtAuth\Contracts\IAuthService;
use SMSkin\JwtAuth\Contracts\IRefreshTokenStorage;
use SMSkin\JwtAuth\JwtGuard;
use SMSkin\JwtAuth\Support\Crypto;
use SMSkin\JwtAuth\Support\RefreshTokenStorage;

class ServiceProvider extends \Illuminate\Support\ServiceProvider
{
    public function boot()
    {
        $this->loadConfig();
    }

    public function register()
    {
        $this->registerConfig();

        $this->app->bind(IRefreshTokenStorage::class, RefreshTokenStorage::class);
        $this->app->bind(IAuthService::class, AuthService::class);

        $this->app->singleton(Crypto::class, static function () {
            return new Crypto(config('jwt.core.secret_key'));
        });

        Auth::extend('jwt', static function (Application $app, string $name, array $config) {
            return new JwtGuard(
                $app['auth']->createUserProvider($config['provider']),
                $app['request'],
                $app->make(IAuthService::class)
            );
        });
    }

    private function loadConfig()
    {
        $configPath = __DIR__ . '/../../config/jwt.php';
        /** @noinspection PhpPossiblePolymorphicInvocationInspection */
        $this->publishes([
            $configPath => app()->configPath('jwt.php'),
        ], 'jwt');
    }

    private function registerConfig()
    {
        $configPath = __DIR__ . '/../../config/jwt.php';
        $this->mergeConfigFrom($configPath, 'jwt');
    }
}
