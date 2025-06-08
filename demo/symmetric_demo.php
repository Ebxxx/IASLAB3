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

// Function to decrypt data
function decryptUserData($userData, $username, $method, $keyManager, $aesEncryption, $chachaEncryption) {
    try {
        // Get the stored key
        $key = $keyManager->getKey($username, $method === 'AES-GCM' ? 'aes' : 'chacha');
        
        // Use a consistent IV/nonce derived from the username and key (12 bytes)
        $ivNonce = substr(hash('sha256', $username . base64_encode($key), true), 0, 12);
        
        // Decrypt data
        if ($method === 'AES-GCM') {
            // For AES-GCM, we need to handle the authentication tag
            $tag = substr(hash('sha256', $userData['name'], true), 0, 16);
            
            return [
                'name' => $aesEncryption->decrypt($userData['name'], $key, $ivNonce, $tag),
                'phone_number' => $aesEncryption->decrypt($userData['phone_number'], $key, $ivNonce, $tag),
                'address' => $aesEncryption->decrypt($userData['address'], $key, $ivNonce, $tag)
            ];
        } else {
            return [
                'name' => $chachaEncryption->decrypt($userData['name'], $key, $ivNonce),
                'phone_number' => $chachaEncryption->decrypt($userData['phone_number'], $key, $ivNonce),
                'address' => $chachaEncryption->decrypt($userData['address'], $key, $ivNonce)
            ];
        }
    } catch (Exception $e) {
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
            
            // Generate IV/nonce (12 bytes as required by both encryption classes)
            $ivNonce = random_bytes(12);
            
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
                
                // Store in database
                $sql = "INSERT INTO personal_data1 (username, name, phone_number, address) 
                       VALUES (?, ?, ?, ?)";
                $stmt = $pdo->prepare($sql);
                $stmt->execute([
                    $_POST['username'],
                    $encryptedName['ciphertext'],
                    $encryptedPhone['ciphertext'],
                    $encryptedAddress['ciphertext']
                ]);
                
            } else {
                $encryptedName = $chachaEncryption->encrypt($data['name'], $key, $ivNonce);
                $encryptedPhone = $chachaEncryption->encrypt($data['phone_number'], $key, $ivNonce);
                $encryptedAddress = $chachaEncryption->encrypt($data['address'], $key, $ivNonce);
                
                // Store in database
                $sql = "INSERT INTO personal_data1 (username, name, phone_number, address) 
                       VALUES (?, ?, ?, ?)";
                $stmt = $pdo->prepare($sql);
                $stmt->execute([
                    $_POST['username'],
                    $encryptedName,
                    $encryptedPhone,
                    $encryptedAddress
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
        // Try both encryption methods
        $decrypted = decryptUserData($row, $row['username'], 'AES-GCM', $keyManager, $aesEncryption, $chachaEncryption);
        if (!$decrypted) {
            $decrypted = decryptUserData($row, $row['username'], 'CHACHA20', $keyManager, $aesEncryption, $chachaEncryption);
        }
        
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
            <p><strong>Created:</strong> <?php echo htmlspecialchars($record['created_at']); ?></p>
            
            <?php if ($record['decrypted']): ?>
                <h4>Decrypted Data:</h4>
                <p><strong>Name:</strong> <?php echo htmlspecialchars($record['decrypted']['name']); ?></p>
                <p><strong>Phone:</strong> <?php echo htmlspecialchars($record['decrypted']['phone_number']); ?></p>
                <p><strong>Address:</strong> <?php echo htmlspecialchars($record['decrypted']['address']); ?></p>
            <?php else: ?>
                <p><em>Unable to decrypt this record</em></p>
            <?php endif; ?>
        </div>
    <?php endforeach; ?>
    
</body>
</html> 