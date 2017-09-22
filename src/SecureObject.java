import java.io.StringWriter;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class SecureObject implements java.io.Serializable {

	private static final long serialVersionUID = 1L;
	private String header;
	private String payload;
	private String integrity;
	private String name;

	public SecureObject(String header, String payload, String name) {
		this.header = header;
		this.payload = payload;
		this.name = name;
	}

	public String getHeader() {
		return this.header;
	}

	public String getPayload() {
		return this.payload;
	}

	public String getName() {
		return this.name;
	}

	public void setIntegrity(String integrity) {
		this.integrity = integrity;
	}

	public String getIntegrity() {
		return this.integrity;
	}

	public static String createHMAC(String algorithm, String secretKey, String message)
			throws NoSuchAlgorithmException, InvalidKeyException {

		SecretKey key = new SecretKeySpec(secretKey.getBytes(), algorithm);
		Mac mac = Mac.getInstance(algorithm, new BouncyCastleProvider());
		mac.init(key);
		mac.update(message.getBytes());
		byte[] encrypted = mac.doFinal();
		StringWriter writer = new StringWriter();
		for (byte b : encrypted) {
			writer.append(String.format("%02x", b));
		}

		return writer.toString();

	}

	public static String encryptString(Key derivedAESKey, String str) throws Exception {

		byte[] utf8 = str.getBytes("UTF-8");
		Cipher cipher = Cipher.getInstance("AES");
		cipher.init(Cipher.ENCRYPT_MODE, derivedAESKey);
		byte[] encrypted = cipher.doFinal(utf8);
		String encryptedEncoded = Base64.getEncoder().encodeToString(encrypted);
		return encryptedEncoded;
	}

	public static String decryptString(Key derivedAESKey2, String str) throws Exception {

		byte[] decoded = Base64.getDecoder().decode(str);
		Cipher cipher = Cipher.getInstance("AES");
		cipher.init(Cipher.DECRYPT_MODE, derivedAESKey2);
		String decryptedDecoded = new String(cipher.doFinal(decoded));
		return decryptedDecoded;
	}

}