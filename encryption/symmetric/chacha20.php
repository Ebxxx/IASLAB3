<?php
class ChaCha20_Encryption {
    public function encrypt($plaintext, $key, $nonce) {
        if (strlen($key) !== 32) {
            throw new Exception("Key must be 32 bytes long.");
        }
        if (strlen($nonce) !== 12) {
            throw new Exception("Nonce must be 12 bytes long.");
        }
        // Pad nonce to 16 bytes for OpenSSL ChaCha20
        $paddedNonce = str_pad($nonce, 16, "\0");
        $ciphertext = openssl_encrypt($plaintext, 'chacha20', $key, OPENSSL_RAW_DATA, $paddedNonce);
        return base64_encode($ciphertext);
    }

    public function decrypt($ciphertext, $key, $nonce) {
        if (strlen($key) !== 32) {
            throw new Exception("Key must be 32 bytes long.");
        }
        if (strlen($nonce) !== 12) {
            throw new Exception("Nonce must be 12 bytes long.");
        }
        // Pad nonce to 16 bytes for OpenSSL ChaCha20
        $paddedNonce = str_pad($nonce, 16, "\0");
        $ciphertext = base64_decode($ciphertext);
        return openssl_decrypt($ciphertext, 'chacha20', $key, OPENSSL_RAW_DATA, $paddedNonce);
    }
}
?> 