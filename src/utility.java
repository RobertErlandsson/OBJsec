import java.io.UnsupportedEncodingException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;

import javax.crypto.spec.SecretKeySpec;

public class utility {

	public static Key deriveAESKeyServer(PublicKey pubKey, PublicKey pubKey2, PrivateKey privateKey)
			throws NoSuchAlgorithmException, UnsupportedEncodingException {
		byte[] secret = DiffieHellman.sharedSecret(pubKey2, privateKey);
		MessageDigest hash = MessageDigest.getInstance("SHA-256");
		hash.update(secret);
		hash.update(pubKey.getEncoded());
		hash.update(pubKey2.getEncoded());
		byte[] derivedKey = hash.digest();
		//Key aesDerivedKey = new SecretKeySpec(derivedKey, "AES");
		System.out.println("after digest" + Arrays.toString(derivedKey));
		derivedKey = "tFEnHw8NvgBQYhMXnnZK4HZNh9QC7sGSqcI1oZf0fs6c49baB2CxWiATrx4cVjXLJPIrpt3yk8DQ59tefMbVTrOlqGeWxPvW06eqtlg3X0mF8YIxVK5IwiMs7i3SNPOn".getBytes("UTF-8");
		System.out.println("after text" + Arrays.toString(derivedKey));
		derivedKey = Arrays.copyOf(derivedKey, 16);
		System.out.println("after arraycopy" + Arrays.toString(derivedKey));
		Key aesDerivedKey= new SecretKeySpec(derivedKey, "AES");
		return aesDerivedKey;
	}
	public static Key deriveAESKeyClient(PublicKey pubKey, PublicKey pubKey2, PrivateKey privateKey)
			throws NoSuchAlgorithmException, UnsupportedEncodingException {
		byte[] secret = DiffieHellman.sharedSecret(pubKey, privateKey);
		MessageDigest hash = MessageDigest.getInstance("SHA-256");
		hash.update(secret);
		hash.update(pubKey.getEncoded());
		hash.update(pubKey2.getEncoded());
		byte[] derivedKey = hash.digest();
		//Key aesDerivedKey = new SecretKeySpec(derivedKey, "AES");
		System.out.println("after digest" + Arrays.toString(derivedKey));
		derivedKey = "tFEnHw8NvgBQYhMXnnZK4HZNh9QC7sGSqcI1oZf0fs6c49baB2CxWiATrx4cVjXLJPIrpt3yk8DQ59tefMbVTrOlqGeWxPvW06eqtlg3X0mF8YIxVK5IwiMs7i3SNPOn".getBytes("UTF-8");
		System.out.println("after text" + Arrays.toString(derivedKey));
		derivedKey = Arrays.copyOf(derivedKey, 16);
		System.out.println("after arraycopy" + Arrays.toString(derivedKey));
		Key aesDerivedKey= new SecretKeySpec(derivedKey, "AES");
		return aesDerivedKey;
	}
}
