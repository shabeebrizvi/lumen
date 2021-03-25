<?php

/** @var \Laravel\Lumen\Routing\Router $router */

/*
|--------------------------------------------------------------------------
| Application Routes
|--------------------------------------------------------------------------
|
| Here is where you can register all of the routes for an application.
| It is a breeze. Simply tell Lumen the URIs it should respond to
| and give it the Closure to call when that URI is requested.
|
 */

$router->group(['namespace' => 'Auth'], function () use ($router) {
    $router->post('register', 'LoginController@register');
    $router->post('login', 'LoginController@login');
    $router->get('profile', 'LoginController@profile');
    $router->get('refresh', 'LoginController@refresh');
    $router->post('logout', 'LoginController@logout');
});
