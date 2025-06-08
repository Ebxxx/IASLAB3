<?php
class SymmetricKeyManagement {
    private $keyStorePath;
    
    public function __construct($keyStorePath = '../../keys/symmetric') {
        // Convert relative path to absolute path
        if (!str_starts_with($keyStorePath, '/') && !preg_match('/^[A-Za-z]:\\\/', $keyStorePath)) {
            $keyStorePath = __DIR__ . DIRECTORY_SEPARATOR . $keyStorePath;
        }
        
        $this->keyStorePath = $keyStorePath;
        
        // Create directory with secure permissions
        if (!file_exists($this->keyStorePath)) {
            if (!mkdir($this->keyStorePath, 0700, true)) {
                throw new Exception("Failed to create key store directory at: " . $this->keyStorePath);
            }
        }
        
        // Ensure directory is secure
        if (!chmod($this->keyStorePath, 0700)) {
            throw new Exception("Failed to set secure permissions on key store directory");
        }
    }
    
    /**
     * Generate new encryption keys for both AES-GCM and ChaCha20 or specific method
     * @param string $userId User identifier
     * @param string $method Optional: specific method ('aes' or 'chacha'), if null generates both
     * @return array Array containing the generated keys
     */
    public function generateKeys($userId, $method = null) {
        try {
            $keys = [];
            
            if ($method === null || $method === 'aes') {
                // Generate AES key
                $aesKey = random_bytes(32);    // 256-bit key for AES-GCM
                $this->storeKey($userId, 'aes', $aesKey);
                $keys['aes'] = base64_encode($aesKey);
            }
            
            if ($method === null || $method === 'chacha') {
                // Generate ChaCha20 key
                $chachaKey = random_bytes(32);  // 256-bit key for ChaCha20
                $this->storeKey($userId, 'chacha', $chachaKey);
                $keys['chacha'] = base64_encode($chachaKey);
            }
            
            if (empty($keys)) {
                throw new Exception("Invalid encryption method specified: $method");
            }
            
            return $keys;
        } catch (Exception $e) {
            throw new Exception("Failed to generate keys: " . $e->getMessage());
        }
    }
    
    /**
     * Store an encryption key
     * @param string $userId User identifier
     * @param string $type Key type ('aes' or 'chacha')
     * @param string $key Raw key bytes
     */
    private function storeKey($userId, $type, $key) {
        $filename = $this->getKeyPath($userId, $type);
        
        // Encrypt the key before storing (using system's encryption)
        $encryptedKey = $this->encryptKeyForStorage($key);
        
        // Store with secure permissions
        if (file_put_contents($filename, $encryptedKey, LOCK_EX) === false) {
            throw new Exception("Failed to write key file: $filename");
        }
        
        // Set secure file permissions
        if (!chmod($filename, 0600)) {
            unlink($filename);
            throw new Exception("Failed to set secure permissions on key file");
        }
    }
    
    /**
     * Retrieve an encryption key
     * @param string $userId User identifier
     * @param string $type Key type ('aes' or 'chacha')
     * @return string Raw key bytes
     */
    public function getKey($userId, $type) {
        $filename = $this->getKeyPath($userId, $type);
        
        if (!file_exists($filename)) {
            throw new Exception("Key file not found: $filename");
        }
        
        $encryptedKey = file_get_contents($filename);
        if ($encryptedKey === false) {
            throw new Exception("Failed to read key file: $filename");
        }
        
        // Decrypt the stored key
        return $this->decryptStoredKey($encryptedKey);
    }
    
    /**
     * Delete keys for a user
     * @param string $userId User identifier
     */
    public function deleteKeys($userId) {
        $types = ['aes', 'chacha'];
        foreach ($types as $type) {
            $filename = $this->getKeyPath($userId, $type);
            if (file_exists($filename)) {
                if (!unlink($filename)) {
                    throw new Exception("Failed to delete key file: $filename");
                }
            }
        }
    }
    
    /**
     * Check if keys exist for a user
     * @param string $userId User identifier
     * @return array Status of each key type
     */
    public function checkKeys($userId) {
        return [
            'aes' => file_exists($this->getKeyPath($userId, 'aes')),
            'chacha' => file_exists($this->getKeyPath($userId, 'chacha'))
        ];
    }
    
    /**
     * Get the full path for a key file
     * @param string $userId User identifier
     * @param string $type Key type
     * @return string Full path to key file
     */
    private function getKeyPath($userId, $type) {
        return $this->keyStorePath . DIRECTORY_SEPARATOR . 
               $type . '_key_' . preg_replace('/[^a-zA-Z0-9_-]/', '', $userId) . '.key';
    }
    
    /**
     * Encrypt a key for storage
     * @param string $key Raw key bytes
     * @return string Encrypted key
     */
    private function encryptKeyForStorage($key) {
        // Generate a storage key derived from system-specific information
        $storageKey = hash('sha256', php_uname(), true);
        $iv = random_bytes(16);
        
        // Encrypt the key
        $encrypted = openssl_encrypt(
            $key,
            'aes-256-gcm',
            $storageKey,
            OPENSSL_RAW_DATA,
            $iv,
            $tag
        );
        
        // Combine IV, tag, and encrypted key for storage
        return base64_encode($iv . $tag . $encrypted);
    }
    
    /**
     * Decrypt a stored key
     * @param string $encryptedData Base64 encoded encrypted key data
     * @return string Raw key bytes
     */
    private function decryptStoredKey($encryptedData) {
        $data = base64_decode($encryptedData);
        
        // Extract IV, tag, and encrypted key
        $iv = substr($data, 0, 16);
        $tag = substr($data, 16, 16);
        $encrypted = substr($data, 32);
        
        // Generate the same storage key
        $storageKey = hash('sha256', php_uname(), true);
        
        // Decrypt the key
        $decrypted = openssl_decrypt(
            $encrypted,
            'aes-256-gcm',
            $storageKey,
            OPENSSL_RAW_DATA,
            $iv,
            $tag
        );
        
        if ($decrypted === false) {
            throw new Exception("Failed to decrypt stored key");
        }
        
        return $decrypted;
    }
}

// Example usage:
if (php_sapi_name() === 'cli') {
    try {
        $keyManager = new SymmetricKeyManagement();
        
        // Generate new keys
        echo "Generating new keys...\n";
        $keys = $keyManager->generateKeys('user123');
        echo "Generated AES Key: " . $keys['aes'] . "\n";
        echo "Generated ChaCha Key: " . $keys['chacha'] . "\n";
        
        // Check key existence
        echo "\nChecking keys...\n";
        $status = $keyManager->checkKeys('user123');
        echo "AES Key exists: " . ($status['aes'] ? 'Yes' : 'No') . "\n";
        echo "ChaCha Key exists: " . ($status['chacha'] ? 'Yes' : 'No') . "\n";
        
        // Retrieve keys
        echo "\nRetrieving keys...\n";
        $aesKey = $keyManager->getKey('user123', 'aes');
        $chachaKey = $keyManager->getKey('user123', 'chacha');
        echo "Retrieved AES Key: " . base64_encode($aesKey) . "\n";
        echo "Retrieved ChaCha Key: " . base64_encode($chachaKey) . "\n";
        
    } catch (Exception $e) {
        echo "Error: " . $e->getMessage() . "\n";
    }
}
?>