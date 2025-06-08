<?php
require_once '../encryption/asymmetric/ntru_encryption.php';
require_once '../encryption/asymmetric/key_management.php';
require_once '../config/database.php';

// Initialize encryption classes
$ntruEncryption = new NTRUEncryption();
$keyManager = new KeyManagement();

// Handle form submission
$message = '';
$allRecords = [];

// Function to decrypt NTRU data
function decryptNTRUData($userData, $username, $keyManager, $ntruEncryption) {
    try {
        // Start timing for decryption speed measurement
        $startTime = microtime(true);
        
        // Get the stored NTRU keys
        $ntruKeys = $keyManager->getNTRUKeys($username);
        
        // Prepare encrypted fields
        $encryptedFields = ['credit_card_number', 'expiration_date', 'cvv'];
        $decrypted = [];
        
        foreach ($encryptedFields as $field) {
            if (isset($userData[$field]) && !empty($userData[$field])) {
                try {
                    // Decrypt the stored encrypted data
                    $decrypted[$field] = $ntruEncryption->decrypt($userData[$field], $ntruKeys['private']);
                    
                } catch (Exception $e) {
                    error_log("Failed to decrypt field $field: " . $e->getMessage());
                    $decrypted[$field] = "[Decryption failed]";
                }
            }
        }
        
        // End timing and add to result
        $endTime = microtime(true);
        $decryptionTime = ($endTime - $startTime) * 1000; // Convert to milliseconds
        $decrypted['decryption_time'] = $decryptionTime;
        
        return $decrypted;
    } catch (Exception $e) {
        error_log("NTRU Decryption failed for user $username: " . $e->getMessage());
        return null;
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    try {
        if (isset($_POST['action']) && $_POST['action'] === 'encrypt') {
            // Check if GMP extension is loaded
            if (!extension_loaded('gmp')) {
                throw new Exception("GMP extension is not loaded. Please enable it in php.ini for NTRU encryption");
            }
            
            // Generate NTRU keys for the user
            try {
                $userKeys = $keyManager->generateUserKeys($_POST['username']);
                $ntruKeys = $userKeys['ntru'];
                
                if (!$ntruKeys || !isset($ntruKeys['public']) || !isset($ntruKeys['private'])) {
                    throw new Exception("Failed to generate NTRU keys - no keys returned");
                }
            } catch (Exception $e) {
                throw new Exception("NTRU Key generation failed: " . $e->getMessage());
            }
            
            // Start timing for encryption speed measurement
            $startTime = microtime(true);
            
            // Prepare data for encryption
            $data = [
                'credit_card_number' => $_POST['credit_card_number'],
                'expiration_date' => $_POST['expiration_date'],
                'cvv' => $_POST['cvv']
            ];
            
            // Encrypt each field using NTRU
            $encryptedData = [];
            
            foreach ($data as $field => $value) {
                try {
                    $encryptedData[$field] = $ntruEncryption->encrypt($value, $ntruKeys['public']);
                } catch (Exception $e) {
                    throw new Exception("NTRU Encryption failed for field $field: " . $e->getMessage());
                }
            }
            
            // End timing
            $endTime = microtime(true);
            $encryptionTime = ($endTime - $startTime) * 1000; // Convert to milliseconds
            
            // Store in database
            $sql = "INSERT INTO personal_data3 (username, credit_card_number, expiration_date, cvv) 
                   VALUES (?, ?, ?, ?)";
            $stmt = $pdo->prepare($sql);
            $success = $stmt->execute([
                $_POST['username'],
                $encryptedData['credit_card_number'],
                $encryptedData['expiration_date'],
                $encryptedData['cvv']
            ]);
            
            if (!$success) {
                throw new Exception("Failed to store encrypted data in database");
            }
            
            $message = sprintf(
                "Data encrypted and stored successfully using NTRU Post-Quantum Encryption (Encryption time: %.2f ms)", 
                $encryptionTime
            );
        }
    } catch (Exception $e) {
        $message = "Error: " . $e->getMessage();
        // Log the full error for debugging
        error_log("NTRU Demo Error: " . $e->getMessage() . " | Trace: " . $e->getTraceAsString());
    }
}

// Fetch all records
try {
    $sql = "SELECT * FROM personal_data3 ORDER BY created_at DESC";
    $stmt = $pdo->query($sql);
    while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
        // Decrypt the data
        $decrypted = decryptNTRUData($row, $row['username'], $keyManager, $ntruEncryption);
        
        $allRecords[] = [
            'id' => $row['id'],
            'username' => $row['username'],
            'encrypted' => $row,
            'decrypted' => $decrypted,
            'created_at' => $row['created_at']
        ];
    }
} catch (Exception $e) {
    $message = "Error fetching records: " . $e->getMessage();
}
?>

<!DOCTYPE html>
<html>
<head>
    <title>NTRU Post-Quantum Encryption Demo</title>
</head>
<body>
    <div style="background-color: #f8f9fa; padding: 10px; margin-bottom: 20px; border-bottom: 2px solid #ddd;">
        <h2 style="margin: 0; color: #333;">Encryption Demos</h2>
        <nav style="margin-top: 10px;">
            <a href="chacha&aes_demo.php" style="margin-right: 15px; text-decoration: none; color: #007cba;">AES-GCM & ChaCha20 encryption</a>
            <a href="ecc_demo.php" style="margin-right: 15px; text-decoration: none; color: #007cba;">ECC Encryption</a>
            <a href="homomorphic_demo.php" style="margin-right: 15px; text-decoration: none; color: #007cba;">Homomorphic Encryption</a>
            <strong style="color: #28a745;">NTRU Post-Quantum Encryption</strong>
            <a href="tls_demo.php" style="margin-left: 15px; text-decoration: none; color: #007cba;">TLS v1.3 Demo</a>
        </nav>
    </div>
    
    <h1>NTRU Post-Quantum Encryption Demo</h1>
    
    <?php if ($message): ?>
        <p><strong>Message:</strong> <?php echo htmlspecialchars($message); ?></p>
    <?php endif; ?>
    
    <h2>Encrypt New Credit Card Data</h2>
    <form method="POST">
        <input type="hidden" name="action" value="encrypt">
        
        <p>
            <label>Username:</label><br>
            <input type="text" name="username" required>
        </p>
        
        <p>
            <label>Credit Card Number:</label><br>
            <input type="text" name="credit_card_number" required>
        </p>
        
        <p>
            <label>Expiration Date:</label><br>
            <input type="month" name="expiration_date" required>
        </p>
        
        <p>
            <label>CVV:</label><br>
            <input type="text" name="cvv" required>
        </p>
        
        <p>
            <button type="submit">Encrypt and Store</button>
        </p>
    </form>
        
    <hr>
    
    <h2>Stored Records</h2>
    <?php foreach ($allRecords as $record): ?>
        <div style="margin-bottom: 20px; border-bottom: 1px solid #ccc; padding-bottom: 10px;">
            <h3>Record #<?php echo htmlspecialchars($record['id']); ?></h3>
            <p><strong>Username:</strong> <?php echo htmlspecialchars($record['username']); ?></p>
            <p><strong>Encryption Method:</strong> NTRU (Post-Quantum)</p>
            <p><strong>Created:</strong> <?php echo htmlspecialchars($record['created_at']); ?></p>
            
            <?php if ($record['decrypted']): ?>
                <h4>Decrypted Data:</h4>
                <p><strong>Credit Card Number:</strong> <?php echo htmlspecialchars($record['decrypted']['credit_card_number']); ?></p>
                <p><strong>Expiration Date:</strong> <?php echo htmlspecialchars($record['decrypted']['expiration_date']); ?></p>
                <p><strong>CVV:</strong> <?php echo htmlspecialchars($record['decrypted']['cvv']); ?></p>
                <?php if (isset($record['decrypted']['decryption_time'])): ?>
                    <p><strong>Decryption Speed:</strong> <?php echo number_format($record['decrypted']['decryption_time'], 2); ?> ms</p>
                <?php endif; ?>
            <?php else: ?>
                <p><em>Unable to decrypt this record - key may be missing</em></p>
            <?php endif; ?>
        </div>
    <?php endforeach; ?>
    
</body>
</html>
