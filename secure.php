<?php
/*
 * EXAMPLE CODE ONLY
 * HASHING: Different hashing examples
 * ENCRYPTION: OpenSSL encrypt and decrypt with public and private keys
 * OPENSSL ENCRYPT AND DECRYPT WITH PUBLIC AND PRIVATE KEYS
 */

	echo "<strong>Hashing</strong><br />";
	
	$password = 'moneky123'; // user generated password
	$salt = openssl_random_pseudo_bytes(24);
	
	echo "Salt= $salt<br />";
	
	$md5 = md5($password.$salt);
	echo "MD5 = $md5<br />";
	
	$sha1 = sha1($password.$salt);
	echo "SHA1 = $sha1<br />";
	
	$sha512 = hash('sha512', $password.$salt);
	echo "SHA512 = $sha512<br />";
	
	
	echo "<br />-----------------------------------------<br />";
	echo "<strong>Encryption</strong><br />";
	
	$secretstring = "This is the secret string I want encrypting";
	echo "Secret String = $secretstring <br />";
	
	$encrypted_txt = public_encrypt($secretstring);
	echo "Encrypted Text = $encrypted_txt <br />";
	
	$decrypted_txt = private_decrypt($encrypted_txt);
	echo "Decrypted Text = $decrypted_txt <br />";
	
	echo "DECRYPTION ";
	if( $secretstring === $decrypted_txt ) echo "WORKED";
	else echo "FAILED";
	
	function public_encrypt($plaintext){
		$fp=fopen("./mykey.pub","r");
		$pub_key=fread($fp,8192);
		fclose($fp);
		openssl_get_publickey($pub_key);
		openssl_public_encrypt($plaintext,$crypttext, $pub_key );
		return(base64_encode($crypttext)); 
	}
	
	function private_decrypt($encryptedext){
		$fp=fopen("./mykey.pem","r");
		$priv_key=fread($fp,8192);
		fclose($fp);
		$private_key = openssl_get_privatekey($priv_key);
		openssl_private_decrypt(base64_decode($encryptedext), $decrypted, $private_key);
		return $decrypted;
	}
	