<?php

use Eloquent\Lockbox\Key\KeyFactory;

require __DIR__ . '/../vendor/autoload.php';

$keyFactory = new KeyFactory;
$privateKey = $keyFactory->createPrivateKeyFromFile(__DIR__ . '/fixture/pem/rsa-2048-nopass.private.pem');
$publicKey = $privateKey->publicKey();

$aesKey = mcrypt_create_iv(32);
$ivSize = mcrypt_get_iv_size(MCRYPT_RIJNDAEL_128, MCRYPT_MODE_CBC);
$iv = mcrypt_create_iv($ivSize);

$data = 'One year before the day, she swore to me she knew exactly how this would end.';

$encrypted = sha1($data, true) . $data;
$encrypted = mcrypt_encrypt(MCRYPT_RIJNDAEL_128, $aesKey, pad($encrypted), MCRYPT_MODE_CBC, $iv);
openssl_public_encrypt($aesKey, $encryptedKey, $publicKey->handle());
// var_dump(base64_encode($aesKey), base64_encode($iv), base64_encode($encrypted));
$encrypted = base64_encode($encryptedKey . $iv . $encrypted);

unset($aesKey, $iv, $encryptedKey);

$decrypted = base64_decode($encrypted);
$encryptedKey = substr($decrypted, 0, $privateKey->envelopeSize());
openssl_private_decrypt($encryptedKey, $decryptedKey, $privateKey->handle());
$iv = substr($decrypted, $privateKey->envelopeSize(), $ivSize);
$decrypted = substr($decrypted, $privateKey->envelopeSize() + $ivSize);
// var_dump(base64_encode($decryptedKey), base64_encode($iv), base64_encode($decrypted));
$decrypted = unpad(mcrypt_decrypt(MCRYPT_RIJNDAEL_128, $decryptedKey, $decrypted, MCRYPT_MODE_CBC, $iv));
$hash = substr($decrypted, 0, 20);
$decrypted = substr($decrypted, 20);

var_dump($decrypted, $data === $decrypted, sha1($decrypted, true) === $hash);

function pad($data)
{
    $blockSize = mcrypt_get_block_size(MCRYPT_RIJNDAEL_128, MCRYPT_MODE_CBC);
    $padSize = intval($blockSize - (strlen($data) % $blockSize));

    return $data . str_repeat(chr($padSize), $padSize);
}

function unpad($data)
{
    $padSize = ord(substr($data, -1));
    $padding = substr($data, -$padSize);
    if (str_repeat(chr($padSize), $padSize) !== $padding) {
        die('Padding sux.');
    }

    return substr($data, 0, -$padSize);
}
