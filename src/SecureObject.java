import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class SecureObject implements java.io.Serializable {

	private static final long serialVersionUID = 1L;
	private String header;
	private String payload;
	private String integrity;
	private String name; 

	private SecureObject (String header, String payload, String name) {
		this.header = header;
		this.payload = payload;
		this.name = name;
	}
	public void setIntegrity(String integrity) {
		this.integrity = integrity;
	}
	public String getIntegrity() {
		return this.integrity;
	}
	public String createHMAC(String algorithm, String secretKey, String message)
			throws NoSuchAlgorithmException, InvalidKeyException {
		// Create a key instance using the bytes of our secret key argument and
		// the proper algorithm
		SecretKey key = new SecretKeySpec(secretKey.getBytes(), algorithm);

		// Create a Mac instance using Bouncy Castle as the provider
		// and the specified algorithm
		Mac mac = Mac.getInstance(algorithm, new BouncyCastleProvider());

		// Initialize using the key and update with the data to
		// generate the mac from
		mac.init(key);
		mac.update(message.getBytes());

		// Perform the mac operation
		byte[] encrypted = mac.doFinal();

		StringWriter writer = new StringWriter();

		// Convert to hexadecimal representation
		for (byte b : encrypted) {
			writer.append(String.format("%02x", b));
		}

		return writer.toString();

	}

	public void sendObject(Key derivedAESkey) throws InvalidKeyException, NoSuchAlgorithmException, UnsupportedEncodingException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
		SecureObject encObj = new SecureObject(encryptString(derivedAESkey,this.header), encryptString(derivedAESkey, this.payload), encryptString(derivedAESkey,this.name));
		encObj.setIntegrity(createHMAC("HmacSHA512", "holy", this.header + this.payload));
		ObjectOutputStream out = new ObjectOutputStream(sockSend.getOutputStream());
		out.writeObject(encObj);
		out.close();
	}
	public void receiveObject() throws InvalidKeyException, NoSuchAlgorithmException {
		SecureObject decObj = null;
		
			ObjectInputStream in = new ObjectInputStream(sockReceive.getInputStream());
			decObj = (SecureObject) in.readObject();
			in.close();
			
			decObj.header = decryptString(derivedAESkey ,this.header);
			decObj.payload = decryptString(derivedAESkey ,this.payload);
			decObj.name = decryptString(derivedAESkey ,this.name);
			
		System.out.println("Decrypted Objectify...");
		System.out.println("Header: " + decObj.header);
		System.out.println("Payload: " + decObj.payload);
		System.out.println("Integrity: " + decObj.getIntegrity());

		if(decObj.getIntegrity().equals(createHMAC("HmacSHA512", "holy", decObj.header + decObj.payload))) {
			System.out.println("SecureObject verified");
		} else {
			System.out.println("INTEGRITY UNVERIFIED");
		}
	}

	private String encryptString(Key derivedAESKey, String str) throws NoSuchAlgorithmException, UnsupportedEncodingException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

		byte[] utf8 = str.getBytes("UTF-8");
		Cipher cipher = Cipher.getInstance("AES");
		cipher.init(Cipher.ENCRYPT_MODE, derivedAESKey);
		byte[] encrypted = cipher.doFinal(utf8);
		String encryptedString = new String(encrypted);
		return encryptedString;
	}

	private String decryptString(Key derivedAESKey2, String str) throws NoSuchAlgorithmException, UnsupportedEncodingException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

		Cipher cipher = Cipher.getInstance("AES");
		cipher.init(Cipher.DECRYPT_MODE, derivedAESKey2);
		String decryptedString = new String(cipher.doFinal(str.getBytes("UTF-8")));
		return decryptedString;
	}

	public static void main (String [] args) throws NoSuchAlgorithmException, InvalidKeyException, UnsupportedEncodingException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
		SecureObject obj = new SecureObject("header","payme","claim");
		obj.sendObject(derivedAESkey);
		obj.receiveObject(derivedAESkey);
		
	}

}
