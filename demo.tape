Output demo.gif

Set Shell "bash"
Set FontSize 16
Set Width 1200
Set Height 600

Hide
Type "clear"
Enter
Show

# 1. Sign an Ethereum message (EIP-191)
Type 'signer evm sign-message -k "4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318" -m "Hello, Ethereum!"'
Sleep 500ms
Enter
Sleep 3s

Ctrl+L

# 2. Show Ethereum address
Type 'signer evm address -k "4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318"'
Sleep 500ms
Enter
Sleep 3s

Ctrl+L

# 3. Sign a Bitcoin message
Type 'signer btc sign-message -k "4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318" -m "Hello, Bitcoin!"'
Sleep 500ms
Enter
Sleep 3s

Ctrl+L

# 4. Sign with Solana (Ed25519)
Type 'signer svm sign -k "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60" -m "Hello, Solana!"'
Sleep 500ms
Enter
Sleep 3s

Ctrl+L

# 5. Sui intent-based signing
Type 'signer sui sign-message -k "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60" -m "Hello, Sui!"'
Sleep 500ms
Enter
Sleep 3s

Ctrl+L

# 6. JSON output for scripts & agents
Type 'signer --json evm sign-message -k "4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318" -m "test"'
Sleep 500ms
Enter
Sleep 3s

Ctrl+L

# 7. Sign across multiple chains
Type 'signer cosmos sign-message -k "4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318" -m "Hello, Cosmos!"'
Sleep 500ms
Enter
Sleep 3s

Ctrl+L

# 8. TON Ed25519 signing
Type 'signer ton sign -k "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60" -m "Hello, TON!"'
Sleep 500ms
Enter
Sleep 5s
