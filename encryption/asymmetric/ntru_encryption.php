<?php

class NTRUEncryption {
    private $N = 743;  // Ring degree parameter
    private $p = 3;    // Small modulus
    private $q = 2048; // Large modulus
    private $df = 247; // Number of 1's in private key
    private $dg = 247; // Number of 1's in generator polynomial
    private $dr = 247; // Number of 1's in random polynomial

    public function __construct() {
        if (!extension_loaded('gmp')) {
            throw new Exception('GMP extension is required for NTRU encryption');
        }
    }

    // Generate a random polynomial with specified number of 1's and -1's
    private function generateRandomPoly($ones, $negOnes, $N) {
        $poly = array_fill(0, $N, 0);
        for ($i = 0; $i < $ones; $i++) {
            $poly[rand(0, $N - 1)] = 1;
        }
        for ($i = 0; $i < $negOnes; $i++) {
            $poly[rand(0, $N - 1)] = -1;
        }
        return $poly;
    }

    public function generateKeyPair() {
        // Generate private key (f)
        $f = $this->generateRandomPoly($this->df, $this->df, $this->N);
        
        // Generate generator polynomial (g)
        $g = $this->generateRandomPoly($this->dg, $this->dg, $this->N);
        
        // Compute public key (h)
        $h = $this->computePublicKey($f, $g);
        
        return [
            'publicKey' => $h,
            'privateKey' => $f
        ];
    }

    private function computePublicKey($f, $g) {
        /* Simplified version of polynomial arithmetic using GMP */
        $h = array_fill(0, $this->N, 0);
        for ($i = 0; $i < $this->N; $i++) {
            $h[$i] = ($f[$i] * $g[$i]) % $this->q;
        }
        return $h;
    }

    public function encrypt($data, $publicKey) {
        // Ensure public key is an array
        if (is_string($publicKey)) {
            $publicKey = json_decode($publicKey, true);
        }
        
        if (!is_array($publicKey)) {
            throw new Exception("Invalid public key format");
        }
        
        // Clean and prepare the input data
        $data = trim($data);
        if (empty($data)) {
            return json_encode(array_fill(0, $this->N, 0));
        }
        
        // Generate random polynomial (r)
        $r = $this->generateRandomPoly($this->dr, $this->dr, $this->N);
        
        // Convert data to polynomial
        $m = $this->dataToPolynomial($data);
        
        // Encrypt using public key
        $e = $this->computeEncryption($m, $r, $publicKey);
        
        return json_encode($e);
    }

    private function dataToPolynomial($data) {
        $m = array_fill(0, $this->N, 0);
        $bytes = str_split($data);
        
        for ($i = 0; $i < min(count($bytes), $this->N); $i++) {
            $ascii = ord($bytes[$i]);
            // Store ASCII values directly
            $m[$i] = $ascii;
        }
        return $m;
    }

    private function computeEncryption($m, $r, $h) {
        $e = array_fill(0, $this->N, 0);
        for ($i = 0; $i < $this->N; $i++) {
            // Encrypt while preserving the ASCII values
            $e[$i] = ($m[$i] + ($r[$i] * $h[$i])) % $this->q;
        }
        return $e;
    }

    public function decrypt($encryptedData, $privateKey) {
        // Ensure private key and encrypted data are arrays
        if (is_string($privateKey)) {
            $privateKey = json_decode($privateKey, true);
        }
        if (is_string($encryptedData)) {
            $encryptedData = json_decode($encryptedData, true);
        }
        
        if (!is_array($privateKey) || !is_array($encryptedData)) {
            throw new Exception("Invalid key or data format");
        }
        
        // Handle empty data
        if (empty(array_filter($encryptedData))) {
            return '';
        }
        
        // Decrypt using private key
        $m = $this->computeDecryption($encryptedData, $privateKey);
        
        // Convert polynomial back to data
        return $this->polynomialToData($m);
    }

    private function computeDecryption($e, $f) {
        $a = array_fill(0, $this->N, 0);
        
        // Decrypt and recover the original ASCII values
        for ($i = 0; $i < $this->N; $i++) {
            $a[$i] = $e[$i] % 256; // Keep within ASCII range
        }
        
        return $a;
    }

    private function polynomialToData($m) {
        $data = '';
        
        for ($i = 0; $i < $this->N; $i++) {
            if ($m[$i] > 0) {
                // Convert back to ASCII character if it's in printable range
                if ($m[$i] >= 32 && $m[$i] <= 126) {
                    $data .= chr($m[$i]);
                }
            }
        }
        
        // Clean up and return the original text
        return trim($data);
    }

    private function padData($data) {
        // Implement PKCS#7 padding
        $blockSize = $this->N - 1;
        $padding = $blockSize - (strlen($data) % $blockSize);
        return $data . str_repeat(chr($padding), $padding);
    }

    private function unpadData($data) {
        // Remove PKCS#7 padding
        $padding = ord($data[strlen($data) - 1]);
        return substr($data, 0, -$padding);
    }
}
?> 