<?php
class ECCEncryption {
    private $curve = 'prime256v1';
    
    public function __construct() {
        // Constructor simplified - no hybrid cipher modes
    }
    
    public function generateKeyPair() {
        if (!extension_loaded('openssl')) {
            throw new Exception("OpenSSL extension is not loaded");
        }

        // Try without config first (most reliable)
        $config = array(
            "private_key_type" => OPENSSL_KEYTYPE_EC,
            "curve_name" => $this->curve
        );

        $privateKey = openssl_pkey_new($config);
        
        // If that fails, try with config paths
        if ($privateKey === false) {
            $possiblePaths = [
                "C:/xampp/php/extras/openssl/openssl.cnf",
                "C:/xampp/apache/conf/openssl.cnf",
                "C:/xampp/apache/bin/openssl.cnf",
                "C:/Program Files/OpenSSL/bin/openssl.cnf",
                php_ini_loaded_file() ? dirname(php_ini_loaded_file()) . '/openssl.cnf' : null
            ];

            foreach ($possiblePaths as $path) {
                if ($path && file_exists($path)) {
                    $config['config'] = $path;
                    $privateKey = openssl_pkey_new($config);
                    if ($privateKey !== false) {
                        break;
                    }
                }
            }
        }
        
        if ($privateKey === false) {
            throw new Exception("Failed to generate ECC key: " . openssl_error_string());
        }

        if (!openssl_pkey_export($privateKey, $privateKeyPem, null, isset($config['config']) ? $config : null)) {
            throw new Exception("Failed to export ECC private key: " . openssl_error_string());
        }

        $keyDetails = openssl_pkey_get_details($privateKey);
        if ($keyDetails === false) {
            throw new Exception("Failed to get ECC key details: " . openssl_error_string());
        }

        return [
            'private' => $privateKeyPem,
            'public' => $keyDetails['key']
        ];
    }

    // Elliptic Curve Diffie-Hellman (ECDH) implementation
    public function deriveSharedSecret($privateKey, $publicKey) {
        $privKey = openssl_pkey_get_private($privateKey);
        if ($privKey === false) {
            throw new Exception("Invalid ECC private key");
        }

        $pubKey = openssl_pkey_get_public($publicKey);
        if ($pubKey === false) {
            throw new Exception("Invalid ECC public key");
        }

        $sharedSecret = openssl_pkey_derive($pubKey, $privKey);
        if ($sharedSecret === false) {
            throw new Exception("Failed to derive ECDH shared secret: " . openssl_error_string());
        }

        // Return raw shared secret for ECC native encryption
        return $sharedSecret;
    }
    
    // Native ECC encryption using ECDH-derived key stream
    public function encrypt($data, $recipientPublicKey) {
        // Generate ephemeral key pair for each encryption
        $ephemeralKeyPair = $this->generateKeyPair();
        
        // Derive shared secret using ECDH
        $sharedSecret = $this->deriveSharedSecret($ephemeralKeyPair['private'], $recipientPublicKey);
        
        // Generate encryption key from shared secret
        $encryptionKey = hash('sha256', $sharedSecret, true);
        
        // Generate a unique nonce for this encryption
        $nonce = random_bytes(16);
        
        // Create key stream using HKDF-like expansion
        $keyStream = $this->generateKeyStream($encryptionKey, $nonce, strlen($data));
        
        // XOR the data with the key stream (stream cipher approach)
        $ciphertext = $data ^ $keyStream;
        
        // Create integrity tag using HMAC
        $tag = hash_hmac('sha256', $ciphertext . $nonce, $encryptionKey, true);
        
                $package = [
                    'ephemeral_public_key' => base64_encode($ephemeralKeyPair['public']),
            'nonce' => base64_encode($nonce),
            'ciphertext' => base64_encode($ciphertext),
            'tag' => base64_encode($tag)
                ];
        
        return base64_encode(json_encode($package));
    }
    
    // Native ECC decryption using ECDH-derived key stream
    public function decrypt($encryptedPackage, $recipientPrivateKey) {
        $package = json_decode(base64_decode($encryptedPackage), true);
        if (!$package || !isset($package['ephemeral_public_key'])) {
            throw new Exception("Invalid encrypted package format");
        }
        
        $ephemeralPublicKey = base64_decode($package['ephemeral_public_key']);
        $nonce = base64_decode($package['nonce']);
        $ciphertext = base64_decode($package['ciphertext']);
        $tag = base64_decode($package['tag']);
        
        // Derive the same shared secret using ECDH
        $sharedSecret = $this->deriveSharedSecret($recipientPrivateKey, $ephemeralPublicKey);

        // Generate the same encryption key
        $encryptionKey = hash('sha256', $sharedSecret, true);
        
        // Verify integrity tag
        $expectedTag = hash_hmac('sha256', $ciphertext . $nonce, $encryptionKey, true);
        if (!hash_equals($expectedTag, $tag)) {
            throw new Exception("Authentication tag verification failed");
        }
        
        // Generate the same key stream
        $keyStream = $this->generateKeyStream($encryptionKey, $nonce, strlen($ciphertext));
        
        // XOR to decrypt
        $plaintext = $ciphertext ^ $keyStream;
        
        return $plaintext;
    }
    
    // Generate key stream for encryption/decryption
    private function generateKeyStream($key, $nonce, $length) {
        $keyStream = '';
        $counter = 0;
        
        while (strlen($keyStream) < $length) {
            // Create a unique block for each iteration
            $block = $nonce . pack('N', $counter);
            // Generate pseudorandom bytes using HMAC
            $keyStream .= hash_hmac('sha256', $block, $key, true);
            $counter++;
        }
        
        // Return only the needed length
        return substr($keyStream, 0, $length);
    }
}
?> 