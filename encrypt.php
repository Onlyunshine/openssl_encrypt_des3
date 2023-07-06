<?php

function pkcs5_pad($text, $blocksize)
{
    $pad = $blocksize - (strlen($text) % $blocksize);
    return $text . str_repeat(chr($pad), $pad);
}

function encrypt($str, $key)
{
    $message = $str;
    $iv = '';

    $blocksize = 8;
    $message_padded = $message;
    $message_padded = pkcs5_pad($message_padded, $blocksize);
    if (strlen($message_padded) % $blocksize) {
        $message_padded = str_pad($message_padded, strlen($message_padded) + $blocksize - strlen($message_padded) % $blocksize, "\0");
    }

    $encrypted_openssl = openssl_encrypt($message_padded, "DES-EDE3", $key, OPENSSL_RAW_DATA | OPENSSL_NO_PADDING, $iv);

    return bin2hex($encrypted_openssl);
}

function decrypt($str, $key)
{
    $str = hex2bin($str);
    $iv = '';

    $encrypted_openssl = openssl_decrypt($str, "DES-EDE3", $key, OPENSSL_RAW_DATA | OPENSSL_NO_PADDING, $iv);

    return $encrypted_openssl;
}

/**
 * data示例：
 * "151684588584784623,17918150372346987,PX20221014091307912616733\r\n151684588584784624,17918150372346985,bb12999d74c74676b4b3e967d75f93d1\r\n"
 * 然后进行3des加密(key=09b18f85350148b7abda312ceecf8a4a)
 * cae60c7e623d2d73c2f68ec35e502bd14eae051f62bc7672f710ce655293ad88610e532385f42500d59d2977443da5eaf8a86e8c2e9511675fe832c76297e60bcae60c7e623d2d73c2f68ec35e502bd13dd9579b0e249166f710ce655293ad888668fc4ab0443f5d110361cf653ddf792acfb24d7e9f6c30ac3bcf644c689f4ab1057f4fab3920c9
 * 3des加密结果对比:
 * 卡号加密key与signKey相同
 * 加密的KEY：09b18f85350148b7abda312ceecf8a4a
 * 需要加密的原始数据:123456
 * 加密后的结果为:0419e8d9c570980b
 */
$data = '123456';
$key = '09b18f85350148b7abda312ceecf8a4a';
$encrypt_data = encrypt($data, $key);
echo "\nEncrypted: $encrypt_data\n";

$decrypted_data = decrypt($encrypt_data, $key);
echo "Decrypted: $decrypted_data\n";
