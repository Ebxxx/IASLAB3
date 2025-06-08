<?php
// This code is implemented but not yet integrated with the advanced asymetric encryiption.
// This is a symetric ecnryption.
class AES_GCM_Encryption {
    public function encrypt($plaintext, $key, $iv) {
        if (strlen($key) !== 32) {
            throw new Exception("Key must be 32 bytes long.");
        }
        if (strlen($iv) !== 12) {
            throw new Exception("IV must be 12 bytes long.");
        }
        $tag = '';
        $ciphertext = openssl_encrypt($plaintext, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag);
        return [
            'ciphertext' => base64_encode($ciphertext),
            'tag' => base64_encode($tag)
        ];
    }

    public function decrypt($ciphertext, $key, $iv, $tag) {
        if (strlen($key) !== 32) {
            throw new Exception("Key must be 32 bytes long.");
        }
        if (strlen($iv) !== 12) {
            throw new Exception("IV must be 12 bytes long.");
        }
        $ciphertext = base64_decode($ciphertext);
        $tag = base64_decode($tag);
        return openssl_decrypt($ciphertext, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag);
    }
}

?> 