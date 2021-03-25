<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;

class LoginController extends Controller
{
    /**
     * Create a new controller instance.
     *
     * @return void
     */
    public function __construct()
    {
        $this->middleware('auth:api', ['except' => ['login']]);
    }

    public function register(Request $request)
    {

        $this->validate($request, [
            'name'     => 'required|string',
            'email'    => 'required|email|unique:users',
            'password' => 'required|confirmed',
        ]);

        try {
            $user = new User;

            $user->name     = $request->name;
            $user->email    = $request->email;
            $user->password = Hash::make($request->password);

            if ($user->save()) {
                $code   = 200;
                $output = [
                    'user'    => $user,
                    'code'    => $code,
                    'message' => 'User created successfully.',
                ];
            } else {
                $code   = 500;
                $output = [
                    'code'    => $code,
                    'message' => 'An error occurred while creating user.',
                ];
            }
        } catch (Exception $e) {

            $code   = 500;
            $output = [
                'code'    => $code,
                'message' => 'An error occurred while creating user.',
            ];
        }
        return response()->json($output, $code);
    }

    public function login(Request $request)
    {

        $this->validate($request, [
            'email'    => 'required|email',
            'password' => 'required',
        ]);

        $input = $request->only('email', 'password');

        if (!$authorized = Auth::attempt($input)) {
            $code   = 401;
            $output = [
                'code'    => $code,
                'message' => 'User is not authorized.',
            ];
        } else {
            $code   = 201;
            $token  = $this->respondWithToken($authorized);
            $output = [
                'code'    => $code,
                'message' => 'User logged in successfully.',
                'token'   => $token,
            ];
        }

        return response()->json($output, $code);
    }

    public function profile()
    {
        return response()->json($this->guard()->user());
    }

    public function guard()
    {
        return Auth::guard();
    }

    public function refresh()
    {
        return $this->respondWithToken($this->guard()->refresh());
    }

    public function logout()
    {
        $this->guard()->logout();
        return response()->json(['message' => 'Logged Out!']);
    }

}
