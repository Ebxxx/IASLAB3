<?php
require_once '../encryption/symmetric/aes_gcm.php';
require_once '../encryption/symmetric/chacha20.php';
require_once '../encryption/symmetric/key_management.php';
require_once '../config/database.php';

// Initialize encryption classes
$aesEncryption = new AES_GCM_Encryption();
$chachaEncryption = new ChaCha20_Encryption();
$keyManager = new SymmetricKeyManagement();

// Handle form submission
$message = '';
$decryptedData = null;
$allRecords = [];

// Check and fix database structure
try {
    $sql = "SHOW COLUMNS FROM personal_data1 LIKE 'encryption_method'";
    $stmt = $pdo->query($sql);
    if ($stmt->rowCount() == 0) {
        // Add the encryption_method column
        $sql = "ALTER TABLE personal_data1 ADD COLUMN encryption_method VARCHAR(20)";
        $pdo->exec($sql);
        $message = "Database updated: Added encryption_method column.";
    }
} catch (Exception $e) {
    $message = "Database check failed: " . $e->getMessage();
}

// Function to decrypt data
function decryptUserData($userData, $username, $method, $keyManager, $aesEncryption, $chachaEncryption) {
    try {
        // Get the stored key for the specific method
        $keyType = ($method === 'AES-GCM') ? 'aes' : 'chacha';
        $key = $keyManager->getKey($username, $keyType);
        
        // Use a consistent IV/nonce derived from the username and key (12 bytes)
        $ivNonce = substr(hash('sha256', $username . base64_encode($key), true), 0, 12);
        
        // Decrypt data based on the method used
        if ($method === 'AES-GCM') {
            // For AES-GCM, extract ciphertext and tag
            $nameParts = explode('::', $userData['name']);
            $phoneParts = explode('::', $userData['phone_number']);
            $addressParts = explode('::', $userData['address']);
            
            if (count($nameParts) != 2 || count($phoneParts) != 2 || count($addressParts) != 2) {
                return null; // Invalid format for AES-GCM
            }
            
            return [
                'name' => $aesEncryption->decrypt($nameParts[0], $key, $ivNonce, $nameParts[1]),
                'phone_number' => $aesEncryption->decrypt($phoneParts[0], $key, $ivNonce, $phoneParts[1]),
                'address' => $aesEncryption->decrypt($addressParts[0], $key, $ivNonce, $addressParts[1])
            ];
        } else if ($method === 'CHACHA20') {
            // For ChaCha20, use the ciphertext directly
            return [
                'name' => $chachaEncryption->decrypt($userData['name'], $key, $ivNonce),
                'phone_number' => $chachaEncryption->decrypt($userData['phone_number'], $key, $ivNonce),
                'address' => $chachaEncryption->decrypt($userData['address'], $key, $ivNonce)
            ];
        } else {
            return null; // Unknown encryption method
        }
    } catch (Exception $e) {
        // Add error logging for debugging
        error_log("Decryption failed for user $username with method $method: " . $e->getMessage());
        return null;
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    try {
        if (isset($_POST['action']) && $_POST['action'] === 'encrypt') {
            // Get the encryption method first
            $method = $_POST['encryption_method'];
            $keyType = ($method === 'AES-GCM') ? 'aes' : 'chacha';
            
            // Generate and store key only for the selected method
            $keys = $keyManager->generateKeys($_POST['username'], $keyType);
            
            // Get the key for the selected method
            $key = base64_decode($keys[$keyType]);
            
            // Generate consistent IV/nonce derived from username and key (12 bytes)
            $ivNonce = substr(hash('sha256', $_POST['username'] . base64_encode($key), true), 0, 12);
            
            // Prepare data for encryption
            $data = [
                'name' => $_POST['name'],
                'phone_number' => $_POST['phone_number'],
                'address' => $_POST['address']
            ];
            
            // Encrypt data
            if ($method === 'AES-GCM') {
                $encryptedName = $aesEncryption->encrypt($data['name'], $key, $ivNonce);
                $encryptedPhone = $aesEncryption->encrypt($data['phone_number'], $key, $ivNonce);
                $encryptedAddress = $aesEncryption->encrypt($data['address'], $key, $ivNonce);
                
                // Store in database - combine ciphertext and tag for AES-GCM
                $sql = "INSERT INTO personal_data1 (username, name, phone_number, address, encryption_method) 
                       VALUES (?, ?, ?, ?, ?)";
                $stmt = $pdo->prepare($sql);
                $stmt->execute([
                    $_POST['username'],
                    $encryptedName['ciphertext'] . '::' . $encryptedName['tag'],
                    $encryptedPhone['ciphertext'] . '::' . $encryptedPhone['tag'],
                    $encryptedAddress['ciphertext'] . '::' . $encryptedAddress['tag'],
                    'AES-GCM'
                ]);
                
            } else {
                $encryptedName = $chachaEncryption->encrypt($data['name'], $key, $ivNonce);
                $encryptedPhone = $chachaEncryption->encrypt($data['phone_number'], $key, $ivNonce);
                $encryptedAddress = $chachaEncryption->encrypt($data['address'], $key, $ivNonce);
                
                // Store in database
                $sql = "INSERT INTO personal_data1 (username, name, phone_number, address, encryption_method) 
                       VALUES (?, ?, ?, ?, ?)";
                $stmt = $pdo->prepare($sql);
                $stmt->execute([
                    $_POST['username'],
                    $encryptedName,
                    $encryptedPhone,
                    $encryptedAddress,
                    'CHACHA20'
                ]);
            }
            
            $message = "Data encrypted and stored successfully using " . $method;
            
            // Automatically decrypt and display the newly added data
            $decryptedData = $data;
        }
    } catch (Exception $e) {
        $message = "Error: " . $e->getMessage();
    }
}

// Fetch all records
try {
    $sql = "SELECT * FROM personal_data1 ORDER BY created_at DESC";
    $stmt = $pdo->query($sql);
    while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
        // Use the stored encryption method to decrypt with the correct key
        $encryptionMethod = isset($row['encryption_method']) ? $row['encryption_method'] : 'AES-GCM'; // Default for old records
        $decrypted = decryptUserData($row, $row['username'], $encryptionMethod, $keyManager, $aesEncryption, $chachaEncryption);
        
        $allRecords[] = [
            'id' => $row['id'],
            'username' => $row['username'],
            'encryption_method' => $encryptionMethod,
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
    <title>Symmetric Encryption Demo</title>
</head>
<body>
    <h1>Symmetric Encryption Demo</h1>
    
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
            <label>Encryption Method:</label><br>
            <select name="encryption_method" required>
                <option value="AES-GCM">AES-GCM</option>
                <option value="CHACHA20">ChaCha20</option>
            </select>
        </p>
        
        <p>
            <label>Name:</label><br>
            <input type="text" name="name" required>
        </p>
        
        <p>
            <label>Phone Number:</label><br>
            <input type="text" name="phone_number" required>
        </p>
        
        <p>
            <label>Address:</label><br>
            <textarea name="address" required></textarea>
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
                <p><strong>Name:</strong> <?php echo htmlspecialchars($record['decrypted']['name']); ?></p>
                <p><strong>Phone:</strong> <?php echo htmlspecialchars($record['decrypted']['phone_number']); ?></p>
                <p><strong>Address:</strong> <?php echo htmlspecialchars($record['decrypted']['address']); ?></p>
            <?php else: ?>
                <p><em>Unable to decrypt this record - key may be missing</em></p>
            <?php endif; ?>
        </div>
    <?php endforeach; ?>
    
</body>
</html> 