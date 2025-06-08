<?php
require_once 'asymmetric/ntru_encryption.php';
require_once 'asymmetric/ecc_encryption.php';

class KeyManagement {
    private $keyStorePath;
    private $ntru;
    private $ecc;
    
    public function __construct($keyStorePath = '../keys', $cipherMode = 'AES-256-GCM') {
        // Convert relative path to absolute path
        if (!str_starts_with($keyStorePath, '/') && !preg_match('/^[A-Za-z]:\\\/', $keyStorePath)) {
            $keyStorePath = __DIR__ . DIRECTORY_SEPARATOR . $keyStorePath;
        }
        
        $this->keyStorePath = $keyStorePath;
        $this->ntru = new NTRUEncryption();
        $this->ecc = new ECCEncryption($cipherMode);
        
        // Create directory with full permissions first
        if (!file_exists($this->keyStorePath)) {
            if (!mkdir($this->keyStorePath, 0777, true)) {
                throw new Exception("Failed to create key store directory at: " . $this->keyStorePath);
            }
            // On Windows, mkdir ignores permissions, so we need to explicitly set them
            chmod($this->keyStorePath, 0777);
        }
        
        if (!is_writable($this->keyStorePath)) {
            // Try to make it writable
            if (!chmod($this->keyStorePath, 0777)) {
                throw new Exception("Key store directory is not writable and cannot be made writable: " . $this->keyStorePath);
            }
        }
    }
    
    public function generateUserKeys($userId) {
        try {
            // First ensure the key directory exists with proper permissions
            if (!file_exists($this->keyStorePath)) {
                if (!mkdir($this->keyStorePath, 0777, true)) {
                    throw new Exception("Failed to create key directory: " . $this->keyStorePath);
                }
            }

            // Generate NTRU key pair first
            $ntruKeyPair = $this->ntru->generateKeyPair();
            
            // Generate ECC key pair with better error handling
            $eccKeyPair = null;
            $lastError = null;
            
            try {
                $eccKeyPair = $this->ecc->generateKeyPair();
            } catch (Exception $e) {
                error_log("ECC key generation failed: " . $e->getMessage());
                throw new Exception("Failed to generate ECC keys: " . $e->getMessage());
            }

            if ($eccKeyPair === null) {
                throw new Exception("Failed to generate ECC keys: No key pair was generated");
            }

            // Store keys immediately after generation
            try {
                $this->storeKey($userId, 'ntru_private', $ntruKeyPair['privateKey']);
                $this->storeKey($userId, 'ntru_public', $ntruKeyPair['publicKey']);
                $this->storeKey($userId, 'ecc_private', $eccKeyPair['private']);
                $this->storeKey($userId, 'ecc_public', $eccKeyPair['public']);
            } catch (Exception $e) {
                // If storing fails, cleanup and throw
                $this->cleanupKeyFiles($userId);
                throw new Exception("Failed to store keys: " . $e->getMessage());
            }

            return [
                'ntru' => [
                    'public' => $ntruKeyPair['publicKey'],
                    'private' => $ntruKeyPair['privateKey']
                ],
                'ecc' => [
                    'public' => $eccKeyPair['public'],
                    'private' => $eccKeyPair['private']
                ]
            ];
        } catch (Exception $e) {
            $this->cleanupKeyFiles($userId);
            throw new Exception("Failed to generate and store keys: " . $e->getMessage());
        }
    }
    
    private function storeKey($userId, $type, $key) {
        $filename = $this->getKeyPath($userId, $type);
        // JSON encode array keys before storing
        if (is_array($key)) {
            $key = json_encode($key);
        }
        if (file_put_contents($filename, $key, LOCK_EX) === false) {
            throw new Exception("Failed to write $type key file");
        }
        chmod($filename, 0600);
    }
    
    private function getKeyPath($userId, $type) {
        return $this->keyStorePath . DIRECTORY_SEPARATOR . $type . '_' . $userId . '.pem';
    }
    
    public function getNTRUKeys($userId) {
        $publicKey = file_get_contents($this->getKeyPath($userId, 'ntru_public'));
        $privateKey = file_get_contents($this->getKeyPath($userId, 'ntru_private'));
        
        if ($publicKey === false || $privateKey === false) {
            throw new Exception("Failed to read NTRU keys for user: " . $userId);
        }
        
        return [
            'public' => json_decode($publicKey, true),
            'private' => json_decode($privateKey, true)
        ];
    }
    
    public function getECCKeys($userId) {
        $publicKey = file_get_contents($this->getKeyPath($userId, 'ecc_public'));
        $privateKey = file_get_contents($this->getKeyPath($userId, 'ecc_private'));
        
        if ($publicKey === false || $privateKey === false) {
            throw new Exception("Failed to read ECC keys for user: " . $userId);
        }
        
        return [
            'public' => $publicKey,
            'private' => $privateKey
        ];
    }

    private function cleanupKeyFiles($userId) {
        $keyTypes = ['ntru_private', 'ntru_public', 'ecc_private', 'ecc_public'];
        foreach ($keyTypes as $type) {
            $filepath = $this->getKeyPath($userId, $type);
            if (file_exists($filepath)) {
                @unlink($filepath);
            }
        }
    }
}
?> 
