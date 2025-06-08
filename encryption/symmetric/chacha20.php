<?php
// This code is implemented but not yet integrated with the advanced asymetric encryiption.
// This is a symetric ecnryption.
class ChaCha20_Encryption {
    public function encrypt($plaintext, $key, $nonce) {
        if (strlen($key) !== 32) {
            throw new Exception("Key must be 32 bytes long.");
        }
        if (strlen($nonce) !== 12) {
            throw new Exception("Nonce must be 12 bytes long.");
        }
        $ciphertext = openssl_encrypt($plaintext, 'chacha20', $key, OPENSSL_RAW_DATA, $nonce);
        return base64_encode($ciphertext);
    }

    public function decrypt($ciphertext, $key, $nonce) {
        if (strlen($key) !== 32) {
            throw new Exception("Key must be 32 bytes long.");
        }
        if (strlen($nonce) !== 12) {
            throw new Exception("Nonce must be 12 bytes long.");
        }
        $ciphertext = base64_decode($ciphertext);
        return openssl_decrypt($ciphertext, 'chacha20', $key, OPENSSL_RAW_DATA, $nonce);
    }
}
?> 