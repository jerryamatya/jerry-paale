<?php

/**
 * Created by PhpStorm.
 * User: jerryamatya
 * Date: 8/22/19
 * Time: 5:45 PM
 */
namespace  Jerry\Paale;
use Illuminate\Http\Request;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Key;
class Paale
{
    protected $request;

    function __construct(Request $request)
    {
        $this->request = $request;
    }

    public function verify(Signer $signer, Key $key)
    {
        return
            $this->isTokenValid($signer, $key)
            && !$this->isTokenExpired()
            && $this->ownerMatches();
    }

    public function isTokenValid(Signer $signer, Key $key)
    {
        $access_token = str_replace('Bearer ', '', $this->request->header("Authorization"));

        $token = (new Parser())->parse($access_token);

        return $token->verify($signer, $key);
    }


    public function isTokenExpired()
    {
        $access_token = str_replace('Bearer ', '', $this->request->header("Authorization"));

        $token = (new Parser())->parse($access_token);

        return $token->isExpired();

    }

}