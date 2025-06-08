<?php
require_once __DIR__ . '/../config/database.php';
require_once __DIR__ . '/../encryption/homomorphic/paillier_encryption.php';
require_once __DIR__ . '/../encryption/homomorphic/homomorphic_key_management.php';

// Initialize encryption classes
$paillier = new PaillierEncryption();
$keyManager = HomomorphicKeyManagement::getInstance();

// Handle form submission
$message = '';
$allRecords = [];

// Function to decrypt homomorphic data
function decryptHomomorphicData($userData, $username, $keyManager, $paillier) {
    try {
        // Start timing for decryption speed measurement
        $startTime = microtime(true);
        
        // Get the stored Paillier keys
        $keys = $keyManager->getPaillierKeys($username);
        
        // Decrypt each field
        $decrypted = [];
        $decrypted['base_salary'] = $paillier->decrypt($userData['base_salary'], $keys['private'], $keys['public']);
        $decrypted['bonus'] = $paillier->decrypt($userData['bonus'], $keys['private'], $keys['public']);
        $decrypted['tax_rate'] = $paillier->decrypt($userData['tax_rate'], $keys['private'], $keys['public']);
        
        if (!empty($userData['encrypted_total'])) {
            $decrypted['total'] = $paillier->decrypt($userData['encrypted_total'], $keys['private'], $keys['public']);
        } else {
            $decrypted['total'] = $decrypted['base_salary'] + $decrypted['bonus'];
        }
        
        // Calculate after-tax amount
        $decrypted['after_tax'] = $decrypted['total'] * (1 - $decrypted['tax_rate'] / 100);
        
        // End timing and add to result
        $endTime = microtime(true);
        $decryptionTime = ($endTime - $startTime) * 1000; // Convert to milliseconds
        $decrypted['decryption_time'] = $decryptionTime;
        
        return $decrypted;
    } catch (Exception $e) {
        error_log("Homomorphic Decryption failed for user $username: " . $e->getMessage());
        return null;
    }
}

// Function to perform homomorphic calculations on all records
function calculateCompanyTotals($pdo, $keyManager, $paillier) {
    try {
        $stmt = $pdo->query("SELECT * FROM payroll_data");
        $employees = $stmt->fetchAll(PDO::FETCH_ASSOC);
        
        if (count($employees) == 0) return null;
        
        // Get keys from the first employee (assuming all use same keys for demo)
        $keys = $keyManager->getPaillierKeys($employees[0]['employee_name']);
        
        // Initialize with first employee's encrypted values
        $total_base_encrypted = $employees[0]['base_salary'];
        $total_bonus_encrypted = $employees[0]['bonus'];
        
        // Add all other employees' salaries homomorphically
        for ($i = 1; $i < count($employees); $i++) {
            $total_base_encrypted = $paillier->addEncrypted(
                $total_base_encrypted, 
                $employees[$i]['base_salary'], 
                $keys['public']
            );
            
            $total_bonus_encrypted = $paillier->addEncrypted(
                $total_bonus_encrypted, 
                $employees[$i]['bonus'], 
                $keys['public']
            );
        }
        
        // Decrypt totals
        $total_base_decrypted = $paillier->decrypt($total_base_encrypted, $keys['private'], $keys['public']);
        $total_bonus_decrypted = $paillier->decrypt($total_bonus_encrypted, $keys['private'], $keys['public']);
        
        return [
            'total_employees' => count($employees),
            'total_base_salary' => $total_base_decrypted,
            'total_bonus' => $total_bonus_decrypted,
            'total_payroll' => $total_base_decrypted + $total_bonus_decrypted
        ];
    } catch (Exception $e) {
        return null;
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    try {
        if (isset($_POST['action']) && $_POST['action'] === 'encrypt') {
            // Check if GMP extension is loaded
            if (!extension_loaded('gmp')) {
                throw new Exception("GMP extension is not loaded. Please enable it in php.ini");
            }
            
            // Generate Paillier keys for the user
            try {
                $keys = $keyManager->generateUserKeys($_POST['employee_name']);
                if (!$keys || !isset($keys['public']) || !isset($keys['private'])) {
                    throw new Exception("Failed to generate Paillier keys - no keys returned");
                }
            } catch (Exception $e) {
                throw new Exception("Paillier Key generation failed: " . $e->getMessage());
            }
            
            // Start timing for encryption speed measurement
            $startTime = microtime(true);
            
            // Validate and prepare data for encryption
            $base_salary = intval($_POST['base_salary']);
            $bonus = intval($_POST['bonus']);
            $tax_rate = intval($_POST['tax_rate']);
            
            if ($base_salary <= 0 || $bonus < 0 || $tax_rate < 0 || $tax_rate > 100) {
                throw new Exception("Invalid input values. Base salary must be positive, bonus non-negative, and tax rate between 0-100%");
            }
            
            // Encrypt each field using Paillier
            try {
                $encrypted_base = $paillier->encrypt($base_salary, $keys['public']);
                $encrypted_bonus = $paillier->encrypt($bonus, $keys['public']);
                $encrypted_tax_rate = $paillier->encrypt($tax_rate, $keys['public']);
                
                // Perform homomorphic addition: total = base_salary + bonus
                $encrypted_total = $paillier->addEncrypted($encrypted_base, $encrypted_bonus, $keys['public']);
                
            } catch (Exception $e) {
                throw new Exception("Encryption failed: " . $e->getMessage());
            }
            
            // End timing
            $endTime = microtime(true);
            $encryptionTime = ($endTime - $startTime) * 1000; // Convert to milliseconds
            
            // Store in database
            $sql = "INSERT INTO payroll_data (employee_name, base_salary, bonus, tax_rate, encrypted_total, encryption_method) 
                   VALUES (?, ?, ?, ?, ?, 'paillier')";
            $stmt = $pdo->prepare($sql);
            $success = $stmt->execute([
                $_POST['employee_name'],
                $encrypted_base,
                $encrypted_bonus,
                $encrypted_tax_rate,
                $encrypted_total
            ]);
            
            if (!$success) {
                throw new Exception("Failed to store encrypted data in database");
            }
            
            $message = sprintf(
                "Payroll data encrypted and stored successfully using Paillier homomorphic encryption (Encryption time: %.2f ms)", 
                $encryptionTime
            );
        } elseif (isset($_POST['action']) && $_POST['action'] === 'clear_data') {
            // Clear all payroll data
            $stmt = $pdo->prepare("DELETE FROM payroll_data");
            $stmt->execute();
            $message = "All payroll data cleared successfully.";
        }
    } catch (Exception $e) {
        $message = "Error: " . $e->getMessage();
        error_log("Homomorphic Demo Error: " . $e->getMessage() . " | Trace: " . $e->getTraceAsString());
    }
}

// Fetch all records
try {
    $sql = "SELECT * FROM payroll_data ORDER BY created_at DESC";
    $stmt = $pdo->query($sql);
    while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
        // Decrypt the data
        $decrypted = decryptHomomorphicData($row, $row['employee_name'], $keyManager, $paillier);
        
        $allRecords[] = [
            'id' => $row['id'],
            'employee_name' => $row['employee_name'],
            'encryption_method' => $row['encryption_method'],
            'encrypted' => $row,
            'decrypted' => $decrypted,
            'created_at' => $row['created_at']
        ];
    }
} catch (Exception $e) {
    $message = "Error fetching records: " . $e->getMessage();
}

// Calculate company totals using homomorphic operations
$companyTotals = calculateCompanyTotals($pdo, $keyManager, $paillier);
?>

<!DOCTYPE html>
<html>
<head>
    <title>Homomorphic Encryption Demo</title>
</head>
<body>
    <div style="background-color: #f8f9fa; padding: 10px; margin-bottom: 20px; border-bottom: 2px solid #ddd;">
        <h2 style="margin: 0; color: #333;">Encryption Demos</h2>
        <nav style="margin-top: 10px;">
            <a href="chacha&aes_demo.php" style="margin-right: 15px; text-decoration: none; color: #007cba;">AES-GCM & ChaCha20 encryption</a>
            <a href="ecc_demo.php" style="margin-right: 15px; text-decoration: none; color: #007cba;">ECC Encryption</a>
            <strong style="color: #28a745;">Homomorphic Encryption</strong>
            <a href="post_quantum.php" style="margin-left: 15px; text-decoration: none; color: #007cba;">NTRU Post-Quantum Encryption</a>
            <a href="tls_demo.php" style="margin-left: 15px; text-decoration: none; color: #007cba;">TLS v1.3 Demo</a>
        </nav>
    </div>
    
    <h1>Homomorphic Encryption Demo</h1>
    
    <?php if ($message): ?>
        <p><strong>Message:</strong> <?php echo htmlspecialchars($message); ?></p>
    <?php endif; ?>
    
    <h2>Encrypt New Payroll Data</h2>
    <form method="POST">
        <input type="hidden" name="action" value="encrypt">
        
        <p>
            <label>Employee Name:</label><br>
            <input type="text" name="employee_name" required>
        </p>
        
        <p>
            <label>Base Salary (USD):</label><br>
            <input type="number" name="base_salary" required min="1">
        </p>
        
        <p>
            <label>Bonus (USD):</label><br>
            <input type="number" name="bonus" required min="0">
        </p>
        
        <p>
            <label>Tax Rate (%):</label><br>
            <input type="number" name="tax_rate" required min="0" max="100">
        </p>
        
        <p>
            <button type="submit">Encrypt and Store</button>
        </p>
    </form>
    
    <?php if ($companyTotals): ?>
        <hr>
        <h2>Company Totals (Calculated on Encrypted Data)</h2>
        <p><strong>Total Employees:</strong> <?php echo $companyTotals['total_employees']; ?></p>
        <p><strong>Total Base Salaries:</strong> $<?php echo number_format($companyTotals['total_base_salary']); ?></p>
        <p><strong>Total Bonuses:</strong> $<?php echo number_format($companyTotals['total_bonus']); ?></p>
        <p><strong>Total Payroll:</strong> $<?php echo number_format($companyTotals['total_payroll']); ?></p>
        <p><em>Note: These totals were calculated using homomorphic operations without decrypting individual salaries!</em></p>
    <?php endif; ?>
    
    <hr>
    
    <h2>Stored Records</h2>
    <?php foreach ($allRecords as $record): ?>
        <div style="margin-bottom: 20px; border-bottom: 1px solid #ccc; padding-bottom: 10px;">
            <h3>Record #<?php echo htmlspecialchars($record['id']); ?></h3>
            <p><strong>Employee:</strong> <?php echo htmlspecialchars($record['employee_name']); ?></p>
            <p><strong>Encryption Method:</strong> <?php echo htmlspecialchars($record['encryption_method']); ?> (Homomorphic)</p>
            <p><strong>Created:</strong> <?php echo htmlspecialchars($record['created_at']); ?></p>
            
            <?php if ($record['decrypted']): ?>
                <h4>Decrypted Data:</h4>
                <p><strong>Base Salary:</strong> $<?php echo number_format($record['decrypted']['base_salary']); ?></p>
                <p><strong>Bonus:</strong> $<?php echo number_format($record['decrypted']['bonus']); ?></p>
                <p><strong>Tax Rate:</strong> <?php echo $record['decrypted']['tax_rate']; ?>%</p>
                <p><strong>Total (Homomorphic Sum):</strong> $<?php echo number_format($record['decrypted']['total']); ?></p>
                <p><strong>After Tax:</strong> $<?php echo number_format($record['decrypted']['after_tax'], 2); ?></p>
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
