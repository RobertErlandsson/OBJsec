import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.spec.SecretKeySpec;

public class utility {

	 public static Key derivedAESKey(PublicKey publicKey, PublicKey ServerClient, PrivateKey privateKey) throws NoSuchAlgorithmException{
	    	byte[] secret = DiffieHellman.sharedSecret(ServerClient, privateKey);
			MessageDigest hash = MessageDigest.getInstance("SHA-256");
			hash.update(secret);
			hash.update(ServerClient.getEncoded());
			hash.update(publicKey.getEncoded());
			byte[] derivedKey = hash.digest();
			Key aesDerivedKey = new SecretKeySpec(derivedKey, "AES");
			return aesDerivedKey;
	    }
}
