<?php

class PaillierEncryption {
    private $keyLength = 1024; // Key length in bits

    public function __construct() {
        if (!extension_loaded('gmp')) {
            throw new Exception('GMP extension is required for Paillier encryption');
        }
    }

    // Helper function to generate a random prime number
    private function generatePrime($bits) {
        do {
            $num = gmp_random_bits($bits);
            $num = gmp_setbit($num, $bits - 1); // Ensure the number has exactly $bits bits
        } while (!gmp_prob_prime($num, 50)); // 50 repetitions for high probability
        return $num;
    }

    // Helper function for modular multiplicative inverse
    public function modInverse($a, $m) {
        $m0 = $m;
        $y = 0;
        $x = 1;

        if (gmp_cmp($m, 1) == 0) {
            return 0;
        }

        while (gmp_cmp($a, 1) > 0) {
            $q = gmp_div_q($a, $m);
            $t = $m;

            $m = gmp_mod($a, $m);
            $a = $t;
            $t = $y;

            $y = gmp_sub($x, gmp_mul($q, $y));
            $x = $t;
        }

        if (gmp_cmp($x, 0) < 0) {
            $x = gmp_add($x, $m0);
        }

        return $x;
    }

    // Function to encrypt a value
    public function encrypt($value, $publicKey) {
        if (!is_array($publicKey) || !isset($publicKey['n']) || !isset($publicKey['g'])) {
            throw new Exception('Invalid public key format');
        }

        $n = gmp_init($publicKey['n']);
        $g = gmp_init($publicKey['g']);
        $n2 = gmp_pow($n, 2);
        
        // Convert value to GMP
        $m = gmp_init($value);
        
        // Generate random r
        $r = gmp_random_range(gmp_init(1), gmp_sub($n, 1));
        
        // c = g^m * r^n mod n^2
        $gm = gmp_powm($g, $m, $n2);
        $rn = gmp_powm($r, $n, $n2);
        $c = gmp_mod(gmp_mul($gm, $rn), $n2);
        
        return gmp_strval($c);
    }

    // Function to decrypt a value
    public function decrypt($encryptedValue, $privateKey, $publicKey) {
        if (!is_array($privateKey) || !isset($privateKey['lambda']) || !isset($privateKey['mu'])) {
            throw new Exception('Invalid private key format');
        }
        if (!is_array($publicKey) || !isset($publicKey['n'])) {
            throw new Exception('Invalid public key format');
        }

        $n = gmp_init($publicKey['n']);
        $lambda = gmp_init($privateKey['lambda']);
        $mu = gmp_init($privateKey['mu']);
        $n2 = gmp_pow($n, 2);
        
        // Convert encrypted value to GMP
        $c = gmp_init($encryptedValue);
        
        // m = L(c^lambda mod n^2) * mu mod n
        $x = gmp_powm($c, $lambda, $n2);
        $x = gmp_sub($x, 1);
        $x = gmp_div($x, $n);
        $m = gmp_mod(gmp_mul($x, $mu), $n);
        
        return gmp_intval($m);
    }

    // Function to perform homomorphic addition
    public function addEncrypted($encrypted1, $encrypted2, $publicKey) {
        if (!is_array($publicKey) || !isset($publicKey['n'])) {
            throw new Exception('Invalid public key format');
        }

        $n2 = gmp_pow(gmp_init($publicKey['n']), 2);
        
        // Convert encrypted values to GMP
        $c1 = gmp_init($encrypted1);
        $c2 = gmp_init($encrypted2);
        
        // Homomorphic addition is multiplication modulo n^2
        $result = gmp_mod(gmp_mul($c1, $c2), $n2);
        
        return gmp_strval($result);
    }
}
?>
