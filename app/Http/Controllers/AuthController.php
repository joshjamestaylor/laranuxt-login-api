<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;

use App\Models\User;



class AuthController extends Controller
{
    public function login(Request $request)
    {
        if (!Auth::attempt($request->only('email', 'password'))) {
            return response()->json([
                'message' => 'Invalid login details'
            ], 401);
        }
        $request->session()->regenerate();


        return response()->json(['token' =>
            $request->user()->createToken('token-name')->plainTextToken,
            
        ],200);

    }

    /*const { data: body } = await useFetch('https://minwest.rywal.dev/sanctum/csrf-cookie', {body: 'body' , method: 'GET' })
*/

    public function logout(Request $request)
    {
    // Revoke the token that was used to authenticate the current request...
    $request->user()->currentAccessToken()->delete();

    $request->session()->invalidate();
    $request->session()->regenerateToken();
    }
    public function getUser(Request $request)
    {
    return response()->json([
        'user' => $request->user(),
    ]);
    }


    public function register(Request $request)
    {
        try {




            $user = User::create([
                'name' => $request->name,
                'email' => $request->email,
                'password' => Hash::make($request->password)
            ]);

            return response()->json([
                'status' => true,
                'message' => 'User Created Successfully',
                'token' => $user->createToken("API TOKEN")->plainTextToken
            ], 200);

        } catch (\Throwable $th) {
            return response()->json([
                'status' => false,
                'message' => $th->getMessage()
            ], 500);
        }
    }

}
