<?php

/**
 * Created by PhpStorm.
 * User: jerryamatya
 * Date: 8/22/19
 * Time: 5:37 PM
*/
use PHPUnit\Framework\TestCase;
use Illuminate\Http\Request;
use Jerry\Paale\Paale as JerryPaale;
use Lcobucci\JWT\Signer\Hmac\Sha256;
use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Signer\Key;
class PaaleTest extends TestCase
{
    public function testCanBeInstantiated()
    {
        $request = Request::create(
            "/users/10/posts", "GET", [], [], [], [], null
        );
        $paale = new JerryPaale($request);

        $this->assertInstanceOf(JerryPaale::class, $paale);

    }

    public function testValidatesAccessToken()
    {
        $request = Request::create(
            '/users/10/posts/5', "GET", [], [], [], [], null
        );

        $paale = new JerryPaale($request);

        $this->expectException(InvalidArgumentException::class);

        $this->assertFalse($paale->verify(new Sha256(), new key('123456789')));

        $token = (new Builder())
                    ->issuedBy('jerry')
            ->permittedFor('laxmi')
            ->expiresAt(time()+3600)
            ->getToken(new Sha256(), new key(123456789));
        $request = Request::create(
            "/users/10/posts/5", "GET", [], [], [], [
            'HTTP_AUTHORIZATION'  => "Bearer " . $token,
        ],
            null
        );

        $paale = new JerryPaale($request);
        $this->assertTrue($paale->isTokenValid(new Sha256(), new Key('testing123')));

        $this->assertFalse($paale->isTokenValid(new Sha256(), new Key('testing12')));

    }

    public function testVerifiesExpiryOfAccessToken()
    {
        $token = (new Builder())
            ->issuedBy('jerry')
            ->permittedFor('laxmi')
            ->expiresAt(time() - 3600)
            ->getToken(new Sha256(), new Key('123456789'));

        $request = Request::create(
            "/users/10/posts/5", "GET", [], [], [], [
            'HTTP_AUTHORIZATION'  => "Bearer " . $token,
        ],
            null
        );
        $paale = new JerryPaale($request);

        $this->assertTrue($paale->isTokenExpired());


        $token = (new Builder())
            ->issuedBy('jerry')
            ->permittedFor('laxmi')
            ->expiresAt(time() + 3600)
            ->setSubject("/users/10")
            ->getToken(new Sha256(), new Key('123456789'));

        $request = Request::create(
            "/users/10/posts/5", "GET", [], [], [], [
            'HTTP_AUTHORIZATION'  => "Bearer " . $token,
        ],
            null
        );

        $paale = new JerryPaale($request);

        $this->assertFalse($paale->isTokenExpired());


    }


}