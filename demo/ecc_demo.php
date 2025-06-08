<?php
require_once '../encryption/asymmetric/ecc_encryption.php';
require_once '../encryption/asymmetric/key_management.php';
require_once '../config/database.php';

// Initialize encryption classes
$eccEncryption = new ECCEncryption();
$keyManager = new KeyManagement();

// Handle form submission
$message = '';
$allRecords = [];

// // Check and fix database structure
// try {
//     $message = "ECC Demo ready.";
    
//     // // Debug: Check key directory
//     // $keyDir = dirname(__FILE__) . '/../keys/asymmetric';
//     // if (!is_dir($keyDir)) {
//     //     $message .= " | Key directory created at: " . realpath(dirname($keyDir)) . '/asymmetric';
//     // } else {
//     //     $message .= " | Key directory exists at: " . realpath($keyDir);
//     // }
    
// } catch (Exception $e) {
//     $message = "Database check failed: " . $e->getMessage();
// }

// Function to decrypt ECC data
function decryptECCData($userData, $username, $keyManager, $eccEncryption) {
    try {
        // Start timing for decryption speed measurement
        $startTime = microtime(true);
        
        // Get the stored ECC keys
        $eccKeys = $keyManager->getECCKeys($username);
        
        // Prepare encrypted package for each field
        $encryptedFields = ['email', 'date_of_birth', 'social_security_number', 'occupation'];
        $decrypted = [];
        
        foreach ($encryptedFields as $field) {
            if (isset($userData[$field]) && !empty($userData[$field])) {
                try {
                    // The stored data is already the complete encrypted package
                    $encryptedPackage = $userData[$field];
                    $decrypted[$field] = $eccEncryption->decrypt($encryptedPackage, $eccKeys['private']);
                    
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
        error_log("ECC Decryption failed for user $username: " . $e->getMessage());
        return null;
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    try {
        if (isset($_POST['action']) && $_POST['action'] === 'encrypt') {
            // Check if OpenSSL extension is loaded
            if (!extension_loaded('openssl')) {
                throw new Exception("OpenSSL extension is not loaded. Please enable it in php.ini");
            }
            
            // Generate ECC keys for the user
            try {
                $eccKeys = $keyManager->generateECCKeys($_POST['username']);
                if (!$eccKeys || !isset($eccKeys['public']) || !isset($eccKeys['private'])) {
                    throw new Exception("Failed to generate ECC keys - no keys returned");
                }
            } catch (Exception $e) {
                throw new Exception("ECC Key generation failed: " . $e->getMessage());
            }
            
            // Start timing for encryption speed measurement
            $startTime = microtime(true);
            
            // Prepare data for encryption
            $data = [
                'email' => $_POST['email'],
                'date_of_birth' => $_POST['date_of_birth'],
                'social_security_number' => $_POST['social_security_number'],
                'occupation' => $_POST['occupation']
            ];
            
            // Encrypt each field using ECC
            $encryptedData = [];
            
            foreach ($data as $field => $value) {
                try {
                    $encryptedPackage = $eccEncryption->encrypt($value, $eccKeys['public']);
                    $package = json_decode(base64_decode($encryptedPackage), true);
                    
                    if (!$package || !isset($package['ephemeral_public_key'])) {
                        throw new Exception("Invalid encryption package for field: $field");
                    }
                    
                    // Store the complete encrypted package (base64 encoded JSON)
                    $encryptedData[$field] = $encryptedPackage;
                } catch (Exception $e) {
                    throw new Exception("Encryption failed for field $field: " . $e->getMessage());
                }
            }
            
            // End timing
            $endTime = microtime(true);
            $encryptionTime = ($endTime - $startTime) * 1000; // Convert to milliseconds
            
            // Store in database
            $sql = "INSERT INTO personal_data2 (username, email, date_of_birth, social_security_number, occupation) 
                   VALUES (?, ?, ?, ?, ?)";
            $stmt = $pdo->prepare($sql);
            $success = $stmt->execute([
                $_POST['username'],
                $encryptedData['email'],
                $encryptedData['date_of_birth'],
                $encryptedData['social_security_number'],
                $encryptedData['occupation']
            ]);
            
            if (!$success) {
                throw new Exception("Failed to store encrypted data in database");
            }
            
            $message = sprintf(
                "Data encrypted and stored successfully using ECC with ECDH (Encryption time: %.2f ms)", 
                $encryptionTime
            );
        }
    } catch (Exception $e) {
        $message = "Error: " . $e->getMessage();
        // Log the full error for debugging
        error_log("ECC Demo Error: " . $e->getMessage() . " | Trace: " . $e->getTraceAsString());
    }
}

// Fetch all records
try {
    $sql = "SELECT * FROM personal_data2 ORDER BY created_at DESC";
    $stmt = $pdo->query($sql);
    while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
        // Decrypt the data
        $decrypted = decryptECCData($row, $row['username'], $keyManager, $eccEncryption);
        
        $allRecords[] = [
            'id' => $row['id'],
            'username' => $row['username'],
            'encryption_method' => isset($row['encryption_method']) ? $row['encryption_method'] : 'ECC',
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
    <title>ECC Encryption Demo</title>
</head>
<body>
    <h1>ECC Encryption Demo</h1>
    
    <?php if ($message): ?>
        <p><strong>Message:</strong> <?php echo htmlspecialchars($message); ?></p>
    <?php endif; ?>
    
    <h2>Encrypt New Data</h2>
    <form method="POST">
        <input type="hidden" name="action" value="encrypt">
        
        <p>
            <label>Username:</label><br>
            <input type="text" name="username" required>
        </p>
        
        <p>
            <label>Email:</label><br>
            <input type="email" name="email" required>
        </p>
        
        <p>
            <label>Date of Birth:</label><br>
            <input type="date" name="date_of_birth" required>
        </p>
        
        <p>
            <label>Social Security Number:</label><br>
            <input type="text" name="social_security_number" required>
        </p>
        
        <p>
            <label>Occupation:</label><br>
            <input type="text" name="occupation" required>
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
            <p><strong>Encryption Method:</strong> <?php echo htmlspecialchars($record['encryption_method']); ?></p>
            <p><strong>Created:</strong> <?php echo htmlspecialchars($record['created_at']); ?></p>
            
            <?php if ($record['decrypted']): ?>
                <h4>Decrypted Data:</h4>
                <p><strong>Email:</strong> <?php echo htmlspecialchars($record['decrypted']['email']); ?></p>
                <p><strong>Date of Birth:</strong> <?php echo htmlspecialchars($record['decrypted']['date_of_birth']); ?></p>
                <p><strong>SSN:</strong> <?php echo htmlspecialchars($record['decrypted']['social_security_number']); ?></p>
                <p><strong>Occupation:</strong> <?php echo htmlspecialchars($record['decrypted']['occupation']); ?></p>
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
