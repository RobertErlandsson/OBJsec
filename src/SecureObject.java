import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.StringWriter;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

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

	public SecureObject (String header, String payload, String name) {
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
	// public String createHMAC(String algorithm, String secretKey, String message)
	//		throws NoSuchAlgorithmException, InvalidKeyException {
	//
	//}
	public void objectify() throws InvalidKeyException, NoSuchAlgorithmException {
		SecureObject o = new SecureObject(this.header, this.payload, this.name);
		o.setIntegrity(createHMAC("HmacSHA512", "holy", this.header + this.payload));
		try {
			FileOutputStream fileOut =
					new FileOutputStream("./" + this.name);
			ObjectOutputStream out = new ObjectOutputStream(fileOut);
			out.writeObject(o);
			out.close();
			fileOut.close();
			System.out.printf("Serialized data is saved in ./" + this.name + "\n");
		}catch(IOException i) {
			i.printStackTrace();
		}
		//KRYPTERA EFTERÅT
	}
	public void deObjectify() throws InvalidKeyException, NoSuchAlgorithmException {
		SecureObject d = null;
		try {
			FileInputStream fileIn = new FileInputStream("./" + this.name);
			ObjectInputStream in = new ObjectInputStream(fileIn);
			d = (SecureObject) in.readObject();
			in.close();
			fileIn.close();
		}catch(IOException i) {
			i.printStackTrace();
			return;
		}catch(ClassNotFoundException c) {
			System.out.println("SecureObject class not found");
			c.printStackTrace();
			return;
		}

		//DEKRYPTERA FÖRE
		
		System.out.println("Deserialized Objectify...");
		System.out.println("Header: " + d.header);
		System.out.println("Payload: " + d.payload);
		System.out.println("Integrity: " + d.getIntegrity());
		
		if(d.getIntegrity().equals(createHMAC("HmacSHA512", "holy", d.header + d.payload))) {
			System.out.println("SecureObject verified");
		} else {
			System.out.println("INTEGRITY UNVERIFIED");
		}
	}
	
	public static void main (String [] args) throws NoSuchAlgorithmException, InvalidKeyException {
		SecureObject obj = new SecureObject("header","payme","objectify");
		obj.objectify();
		obj.deObjectify();
		
	}

}
