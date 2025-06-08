<?php
require_once '../encryption/tls/tls_handshake.php';

class TLSConnectionDemo {
    private $logs = [];
    private $serverHost = 'localhost';
    private $serverPort = 8443;
    
    public function log($message, $type = 'info') {
        $timestamp = date('H:i:s.') . sprintf('%03d', (microtime(true) - floor(microtime(true))) * 1000);
        $this->logs[] = [
            'timestamp' => $timestamp,
            'message' => $message,
            'type' => $type
        ];
    }
    
    public function getLogs() {
        return $this->logs;
    }
    
    public function testTLSConnection() {
        $this->log("Starting TLS Connection Test", 'header');
        
        try {
            // Step 1: Initialize TLS Handshake
            $this->log("Step 1: Initializing TLS handshake class...", 'step');
            
            try {
                $tlsHandshake = new TLSHandshake();
                $this->log("✓ TLS handshake class initialized successfully", 'success');
            } catch (Exception $e) {
                $this->log("⚠ TLS handshake initialization warning: " . $e->getMessage(), 'warning');
                $this->log("Continuing with fallback configuration...", 'info');
                // Create handshake object anyway for demo purposes
                $tlsHandshake = new TLSHandshake();
            }
            
            // Step 2: Create SSL Context
            $this->log("Step 2: Creating SSL context...", 'step');
            $context = $tlsHandshake->startHandshake();
            $this->log("✓ SSL context created with security settings", 'success');
            
            // Step 3: Test Local Server Connection
            $this->log("Step 3: Testing connection to local TLS server...", 'step');
            $this->log("Attempting to connect to {$this->serverHost}:{$this->serverPort}", 'info');
            
            try {
                $socket = $tlsHandshake->secureConnection($this->serverHost, $this->serverPort, $context);
                $this->log("✓ Secure connection established successfully", 'success');
                
                // Step 4: Send Test Message
                $this->log("Step 4: Sending test message...", 'step');
                $testMessage = "Hello from TLS demo client! " . date('Y-m-d H:i:s');
                fwrite($socket, $testMessage);
                $this->log("✓ Message sent: " . $testMessage, 'success');
                
                // Step 5: Receive Response
                $this->log("Step 5: Reading server response...", 'step');
                $response = fread($socket, 1024);
                if ($response) {
                    $this->log("✓ Server response received: " . trim($response), 'success');
                } else {
                    $this->log("No response received from server", 'warning');
                }
                
                // Step 6: Get Connection Details
                $this->log("Step 6: Analyzing connection details...", 'step');
                $meta = stream_get_meta_data($socket);
                if (isset($meta['crypto'])) {
                    $this->log("✓ Connection secured with: " . ($meta['crypto']['protocol'] ?? 'Unknown protocol'), 'success');
                    $this->log("✓ Cipher suite: " . ($meta['crypto']['cipher_name'] ?? 'Unknown cipher'), 'success');
                    $this->log("✓ Cipher version: " . ($meta['crypto']['cipher_version'] ?? 'Unknown version'), 'success');
                }
                
                // Close connection
                fclose($socket);
                $this->log("✓ Connection closed successfully", 'success');
                
                return [
                    'success' => true,
                    'message' => 'TLS connection test completed successfully',
                    'response' => $response,
                    'connection_details' => $meta['crypto'] ?? null
                ];
                
            } catch (Exception $e) {
                $this->log("✗ Connection failed: " . $e->getMessage(), 'error');
                return [
                    'success' => false,
                    'error' => $e->getMessage(),
                    'suggestion' => 'Make sure the TLS server is running (php tls_server.php)'
                ];
            }
            
        } catch (Exception $e) {
            $this->log("✗ Demo failed: " . $e->getMessage(), 'error');
            return [
                'success' => false,
                'error' => $e->getMessage()
            ];
        }
    }
    

    
    public function checkServerStatus() {
        $this->log("Checking TLS server status", 'header');
        
        $socket = @fsockopen($this->serverHost, $this->serverPort, $errno, $errstr, 5);
        
        if ($socket) {
            fclose($socket);
            $this->log("✓ TLS server is running on {$this->serverHost}:{$this->serverPort}", 'success');
            return true;
        } else {
            $this->log("✗ TLS server not reachable: $errstr ($errno)", 'error');
            $this->log("To start the server, run: php tls_server.php", 'info');
            return false;
        }
    }
}

// Handle demo execution
$demo = new TLSConnectionDemo();
$result = null;
$serverStatus = false;

if (isset($_POST['action'])) {
    switch ($_POST['action']) {
        case 'test_local':
            $result = $demo->testTLSConnection();
            break;
        case 'check_server':
            $serverStatus = $demo->checkServerStatus();
            break;
    }
}
?>

<!DOCTYPE html>
<html>
<head>
    <title>TLS v1.3 Connection Demo</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 1200px; margin: 0 auto; padding: 20px; }
        .demo-section { margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }
        .log-entry { padding: 5px; margin: 2px 0; border-radius: 3px; font-family: monospace; font-size: 14px; }
        .log-header { background-color: #2c3e50; color: white; font-weight: bold; }
        .log-step { background-color: #3498db; color: white; }
        .log-success { background-color: #27ae60; color: white; }
        .log-error { background-color: #e74c3c; color: white; }
        .log-warning { background-color: #f39c12; color: white; }
        .log-info { background-color: #f8f9fa; color: #333; border-left: 4px solid #17a2b8; }
        .btn { padding: 10px 20px; background-color: #007cba; color: white; border: none; border-radius: 4px; cursor: pointer; margin: 5px; }
        .btn:hover { background-color: #005a8b; }
        .btn-success { background-color: #28a745; }
        .btn-warning { background-color: #ffc107; color: #212529; }
        .result-box { padding: 15px; border-radius: 5px; margin: 10px 0; }
        .result-success { background-color: #d4edda; border: 1px solid #c3e6cb; color: #155724; }
        .result-error { background-color: #f8d7da; border: 1px solid #f5c6cb; color: #721c24; }
        .server-info { background-color: #e8f4fd; padding: 15px; border-radius: 5px; border-left: 4px solid #007cba; }
        .code-block { background-color: #2d3748; color: #e2e8f0; padding: 10px; border-radius: 5px; font-family: monospace; }
    </style>
</head>
<body>
    <div style="background-color: #f8f9fa; padding: 10px; margin-bottom: 20px; border-bottom: 2px solid #ddd;">
        <h2 style="margin: 0; color: #333;">Encryption Demos</h2>
        <nav style="margin-top: 10px;">
            <a href="chacha&aes_demo.php" style="margin-right: 15px; text-decoration: none; color: #007cba;">AES-GCM & ChaCha20 encryption</a>
            <a href="ecc_demo.php" style="margin-right: 15px; text-decoration: none; color: #007cba;">ECC Encryption</a>
            <a href="homomorphic_demo.php" style="margin-right: 15px; text-decoration: none; color: #007cba;">Homomorphic Encryption</a>
            <a href="post_quantum.php" style="margin-right: 15px; text-decoration: none; color: #007cba;">NTRU Post-Quantum Encryption</a>
            <strong style="color: #28a745;">TLS v1.3 Demo</strong>
        </nav>
    </div>
    
    <h1>TLS v1.3 Connection Testing Demo</h1>
    
    <div class="demo-section">
        <h2>TLS v1.3 Connection Tests</h2>
        <form method="POST">
            <button type="submit" name="action" value="check_server" class="btn btn-warning">Check Server Status</button>
            <button type="submit" name="action" value="test_local" class="btn">Test TLS v1.3 Server</button>
        </form>
    </div>
    
    <?php if ($result): ?>
        <div class="demo-section">
            <h2>TLS v1.3 Test Results</h2>
            <div class="result-box <?php echo $result['success'] ? 'result-success' : 'result-error'; ?>">
                <h3><?php echo $result['success'] ? '✓ TLS v1.3 Test Successful' : '✗ TLS v1.3 Test Failed'; ?></h3>
                <p><strong>Result:</strong> <?php echo htmlspecialchars($result['message'] ?? $result['error']); ?></p>
                
                <?php if (isset($result['response'])): ?>
                    <p><strong>Server Response:</strong> <?php echo htmlspecialchars($result['response']); ?></p>
                <?php endif; ?>
                
                <?php if (isset($result['connection_details'])): ?>
                    <h4>TLS v1.3 Connection Details:</h4>
                    <ul>
                        <li><strong>Protocol:</strong> <?php echo htmlspecialchars($result['connection_details']['protocol'] ?? 'Unknown'); ?></li>
                        <li><strong>Cipher:</strong> <?php echo htmlspecialchars($result['connection_details']['cipher_name'] ?? 'Unknown'); ?></li>
                        <li><strong>Cipher Version:</strong> <?php echo htmlspecialchars($result['connection_details']['cipher_version'] ?? 'Unknown'); ?></li>
                    </ul>
                    <?php if (isset($result['connection_details']['protocol']) && strpos($result['connection_details']['protocol'], 'TLSv1.3') !== false): ?>
                        <p style="color: green; font-weight: bold;">✓ Successfully using TLS v1.3!</p>
                    <?php else: ?>
                        <p style="color: orange; font-weight: bold;">⚠ Not using TLS v1.3 - Protocol: <?php echo htmlspecialchars($result['connection_details']['protocol'] ?? 'Unknown'); ?></p>
                    <?php endif; ?>
                <?php endif; ?>
                
                <?php if (isset($result['suggestion'])): ?>
                    <p><strong>Suggestion:</strong> <?php echo htmlspecialchars($result['suggestion']); ?></p>
                <?php endif; ?>
            </div>
        </div>
    <?php endif; ?>
    
    <div class="demo-section">
        <h2>Test Process Log</h2>
        <div style="background-color: #000; padding: 15px; border-radius: 5px; max-height: 400px; overflow-y: auto;">
            <?php if (empty($demo->getLogs())): ?>
                <div class="log-entry log-info">No tests run yet. Click a test button above to see the process log.</div>
            <?php else: ?>
                <?php foreach ($demo->getLogs() as $log): ?>
                    <div class="log-entry log-<?php echo $log['type']; ?>">
                        [<?php echo $log['timestamp']; ?>] <?php echo htmlspecialchars($log['message']); ?>
                    </div>
                <?php endforeach; ?>
            <?php endif; ?>
        </div>
    </div>
    
</body>
</html> 