# The hidden message in 'Lfzcpbse!opu!gpvoe/!Qsftt!G2!up!dpoujovf' decrypted to 'Keyboard not found . Press F1 to continue'.

function decrypt($char) {
	$num = [int][char]$char		# Change the input to int
	$num = $num-1;			# Reduce the int by 1

	return [char]$num 		# Change back to char, return
}

function encrypt($char) {
	$num = [int][char]$char		# Change the input to int
	$num = $num+1;			# Increase the int by 1

	return [char]$num 		# Change back to char, return
}

function decryption($string) {
	$string_list = $string.ToCharArray()				# Create an array containing the characters in $string
	$result_list = foreach ($char in $string_list) {		# Loop through each char in the array, decrypt it
		decrypt($char)
	}

	$result = [string]$result_list					# Convert the result_list to string

	return $result -replace '\s{1}\b','' -replace '\s+', ' '	# Remove double spaces using regexp, return
}

function encryption($string) {
	$string_list = $string.ToCharArray()				# Create an array containing the characters in $string
	$result_list = foreach($char in $string_list) {			# Loop through each char in the array, encrypt it
		encrypt($char)
	}

	return [string]$result_list -replace '\s',''			# Convert the array to a string, and remove all spaces, return
}									# (The spaces of the string itself are kept as '!'.)
									# (We just need to remove additional spaces from converting the array to string)
