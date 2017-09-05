# Create an AES (AesManaged) Object, used by the other functions
function AesObject($key, $IV) {

	$AES = New-Object "System.Security.Cryptography.AesManaged"
	$AES.Mode = [System.Security.Cryptography.CipherMode]::CBC # Cipher Block Chaining
	$AES.Padding = [System.Security.Cryptography.PaddingMode]::Zeros # If padding is needed, zeros will be used
	$AES.BlockSize = 128 # The unit of data that can be de- or encrypted in one operation. Padding is used if the data is less than this value
	$AES.KeySize = 256 # Sets the key size in bits (256 is the max value)
	if ($IV) { # IV; Initialization Vector, used along with the key
		if ($IV.getType().Name -eq "String") {
			$AES.IV = [System.Convert]::FromBase64String($IV) # Converts $IV if string
		} else {
			$AES.IV = $IV
		}
	}

	if ($key) {
		if ($key.getType().Name -eq "String") {
			$AES.Key = [System.Convert]::FromBase64String($key) # Converts $key if string
		} else {
			$AES.Key = $key
		}
	}

	$AES
}

# Create a key used by the AES object
function AesKey() {
	$AES = AesObject
	$AES.GenerateKey()
	[System.Convert]::ToBase64String($AES.Key) # Convert the key array to string
}

# Use AesManaged's encryption to encrypt a given string
function encrypt($key, $unencryptedString) {
	$bytes = [System.Text.Encoding]::UTF8.GetBytes($unencryptedString) # Convert the string input to bytes
	$AES = AesObject $key # Create an AesManaged object
	$encryptor = $AES.CreateEncryptor() # Create the encryptor
	$encryptedData = $encryptor.TransformFinalBlock($bytes, 0, $bytes.Length);
	[byte[]]$fullData = $AES.IV + $encryptedData # Add the IV to the front of the encrypted data
	$AES.Dispose() # Release resources
	[System.Convert]::ToBase64String($fullData)
}

# Use AesManaged's decryption
function decrypt($key, $encryptedStringWithIV) {
	$bytes = [System.Convert]::FromBase64String($encryptedStringWithIV) # Convert to bytes
	$IV = $bytes[0..15] # The encryped string contains the IV, which is stored as the first 16 elements in $bytes
	$AES = AesObject $key $IV
	$decryptor = $AES.CreateDecryptor(); # Create the decryptor
	$unencryptedData = $decryptor.TransformFinalBlock($bytes, 16, $bytes.Length -16);
	$AES.Dispose() # Release resources
	[System.Text.Encoding]::UTF8.GetString($unencryptedData).Trim([char]0)
}

$key = AesKey
echo "AES Key: $key"
echo ""
$unecryptedString = "Fishing trip to Arkansas eating Crazy Crispy Orea Banana Pancakes from Nicaragua"
echo "String to encrypt: $unecryptedString"
echo ""
$encryptedString = encrypt $key $unecryptedString
echo "Encrypted String: $encryptedString"
echo ""
$decryptedString = decrypt $key $encryptedString
echo "Decrypted String: $decryptedString"
