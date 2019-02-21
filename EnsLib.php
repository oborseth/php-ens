<?php

use kornrunner\Keccak;
use kornrunner\Secp256k1;
use kornrunner\Serializer\HexSignatureSerializer;
use Mdanter\Ecc\EccFactory;

class EnsLib
{
	var $key = null;
	var $address = null;
	var $url = null;

	function __construct()
    	{
		require_once dirname(__FILE__).'/phpecc/src/Crypto/Signature/SignatureInterface.php';
		require_once dirname(__FILE__).'/phpecc/src/Crypto/Signature/Signature.php';
		require_once dirname(__FILE__).'/phpecc/src/Crypto/Signature/Signer.php';
		require_once dirname(__FILE__).'/phpecc/src/Util/BinaryString.php';
		require_once dirname(__FILE__).'/phpecc/src/Util/NumberSize.php';
		require_once dirname(__FILE__).'/phpecc/src/Random/RandomNumberGeneratorInterface.php';
		require_once dirname(__FILE__).'/phpecc/src/Random/HmacRandomNumberGenerator.php';
		require_once dirname(__FILE__).'/phpecc/src/Crypto/Key/PrivateKeyInterface.php';
		require_once dirname(__FILE__).'/phpecc/src/Crypto/Key/PrivateKey.php';
		require_once dirname(__FILE__).'/phpecc/src/Serializer/PrivateKey/PrivateKeySerializerInterface.php';
		require_once dirname(__FILE__).'/phpecc/src/Random/RandomNumberGeneratorInterface.php';
		require_once dirname(__FILE__).'/phpecc/src/Random/RandomNumberGenerator.php';
		require_once dirname(__FILE__).'/phpecc/src/Random/RandomGeneratorFactory.php';
		require_once dirname(__FILE__).'/phpecc/src/Primitives/PointInterface.php';
		require_once dirname(__FILE__).'/phpecc/src/Primitives/Point.php';
		require_once dirname(__FILE__).'/phpecc/src/Primitives/GeneratorPoint.php';
		require_once dirname(__FILE__).'/phpecc/src/Primitives/CurveFpInterface.php';
		require_once dirname(__FILE__).'/phpecc/src/Primitives/CurveParameters.php';
		require_once dirname(__FILE__).'/phpecc/src/Primitives/CurveFp.php';
		require_once dirname(__FILE__).'/phpecc/src/Curves/NamedCurveFp.php';
		require_once dirname(__FILE__).'/phpecc/src/Curves/NistCurve.php';
		require_once dirname(__FILE__).'/phpecc/src/Curves/SecgCurve.php';
		require_once dirname(__FILE__).'/phpecc/src/Curves/CurveFactory.php';
		require_once dirname(__FILE__).'/phpecc/src/Math/MathAdapterFactory.php';
		require_once dirname(__FILE__).'/phpecc/src/Math/GmpMathInterface.php';
		require_once dirname(__FILE__).'/phpecc/src/Math/GmpMath.php';
		require_once dirname(__FILE__).'/phpecc/src/Math/ModularArithmetic.php';
		require_once dirname(__FILE__).'/phpecc/src/EccFactory.php';

		require_once dirname(__FILE__).'/php-keccak/src/Keccak.php';

		require_once dirname(__FILE__).'/php-secp256k1/src/Serializer/HexSignatureSerializer.php';
		require_once dirname(__FILE__).'/php-secp256k1/src/Signature/SignatureInterface.php';
		require_once dirname(__FILE__).'/php-secp256k1/src/Signature/Signature.php';
		require_once dirname(__FILE__).'/php-secp256k1/src/Signature/Signer.php';
		require_once dirname(__FILE__).'/php-secp256k1/src/Serializer/HexPrivateKeySerializer.php';
		require_once dirname(__FILE__).'/php-secp256k1/src/Secp256k1.php';
	}

	function ping()
	{
		$response = $this->send('ping', null, 'GET');
		return($response);
	}

	function namehash($name)
	{
		$payload = array();
		$payload['name'] = $name;

		$response = $this->send('namehash', $payload);
		return($response);
	}

	function nonce($name)
	{
		$payload = array();
		$payload['name'] = $name;

		$response = $this->send('nonce', $payload);
		return($response);
	}

	function associate($name, $owner, $nonce, $namehash)
	{
		$payload = array();
		$payload['domain'] = $name;
		$payload['owner'] = $owner;
		$payload['nonce'] = $nonce;

		$namehash = str_replace('0x', '', $namehash);

		$hexnonce = dechex((float)$nonce);
		$nkey = strval(str_replace('0x', '', $owner));
		$paddedAddress = str_pad($nkey, 64, "0", STR_PAD_LEFT);
		$paddedNonce = str_pad($hexnonce, 64, "0", STR_PAD_LEFT);

		$message = $namehash.$paddedAddress.$paddedNonce;
		$message = pack('H*', $message);
		$hashedMessage = Keccak::hash($message, 256);

		$secp256k1 = new Secp256k1();
		$message = $hashedMessage;
		$signature = $secp256k1->sign('0x'.$message, $this->key);
		$r = $signature->getR();
		$s = $signature->getS();
		$v = $signature->getRecoveryParam();
		$signature = '0x'.str_pad($signature->toHex().dechex($v+27), 129, "0", STR_PAD_LEFT);


		$payload['signature'] = $signature;

		$response = $this->send('associate', $payload);
		return($response);
	}

	function query($name)
	{
		$payload = array();
		$payload['name'] = $name;

		$response = $this->send('query', $payload);
		return($response);
	}

	function transactions($tld, $start = 1, $limit = 100)
	{
		$payload = array();
		$payload['tld'] = $tld;
		// start does not appear to work
		// The browser (or proxy) sent a request that this server could not understand.
		//$payload['start'] = $start;
		$payload['limit'] = $limit;

		$response = $this->send('transactions?'.http_build_query($payload), null, 'GET');
		return($response);
	}

	function isRegistrarAuthorised($kid, $address)
	{
		$payload = array();
		$payload['kid'] = $kid;
		$payload['address'] = $address;

		$response = $this->send('is_registrar_authorised', $payload);
		return($response);
	}

	private function send($endpoint, $payload = null, $requestType = 'POST')
	{
		$url = $this->url.$endpoint;

		$ch = curl_init($url);
		if($payload)
		{
			$payload = json_encode($payload);
			curl_setopt($ch, CURLOPT_POSTFIELDS, $payload);
		}
		curl_setopt($ch, CURLOPT_HTTPHEADER, array('Content-Type:application/json'));
		curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);

		$response = curl_exec($ch);
		curl_close($ch);

		$responseJson = json_decode($response);

		if($responseJson)
			return($responseJson);
		else
			return($response);
	}
}
