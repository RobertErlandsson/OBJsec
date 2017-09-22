import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import javax.crypto.KeyAgreement;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;

public class DiffieHellman {

	public static KeyPair genKeys() throws Exception {
		try {
			Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
			ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("prime192v1");
			KeyPairGenerator g;
			g = KeyPairGenerator.getInstance("ECDSA","BC");
			g.initialize(ecSpec);
			KeyPair pair = g.generateKeyPair();
			return pair;

		} catch (Exception e) {
			return null;
		}
	}

	public static PublicKey getPublicKeyFromByte(byte[] serverKeyByte) {
		try {
			KeyFactory keyfactor = KeyFactory.getInstance("ECDSA");
			PublicKey otherPublicKey = keyfactor.generatePublic(new X509EncodedKeySpec(serverKeyByte));
			return otherPublicKey;		
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			e.printStackTrace();
		}
		return null; 
	}

	public static void sendPublicKey(DatagramSocket sockSend, PublicKey pubKey, InetAddress host, int runPort) {
		byte[] publicKey = pubKey.getEncoded(); // byte

		try {
			sockSend.send(new DatagramPacket(publicKey, publicKey.length, host, runPort));
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	
	public static PublicKey receiveOtherPublicKey(DatagramSocket sockReceive) {
		byte[] buffer = new byte[1024];
		DatagramPacket incoming = new DatagramPacket(buffer, buffer.length);

		try {
			sockReceive.receive(incoming);
		} catch (IOException e) {
			e.printStackTrace();
		}
		byte[] data = incoming.getData();
		byte[] KeyByte = new byte[incoming.getLength()];

		System.arraycopy(data, 0, KeyByte, 0, incoming.getLength());

		PublicKey otherPublicKey = getPublicKeyFromByte(KeyByte);

		if (otherPublicKey != null) {
			return otherPublicKey;
		} else {
			return null;
		}
	}
	
	public static Key deriveAESKey(PublicKey publicKey, PublicKey otherPublicKey, PrivateKey privateKey)
			throws NoSuchAlgorithmException, UnsupportedEncodingException {
		byte[] value;
		
		try {
			KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH");
			keyAgreement.init(privateKey);
			keyAgreement.doPhase(otherPublicKey, true);
			value = keyAgreement.generateSecret();

		} catch (Exception e) {
			return null;
		}
		MessageDigest hash = MessageDigest.getInstance("SHA-256");
		hash.update(value);
		byte[] derivedKey = hash.digest();
		List<ByteBuffer> keys = Arrays.asList(ByteBuffer.wrap(publicKey.getEncoded()), ByteBuffer.wrap(otherPublicKey.getEncoded()));
		Collections.sort(keys);
		hash.update(keys.get(0));
		hash.update(keys.get(1));
		derivedKey = Arrays.copyOf(derivedKey, 16);
		Key aesDerivedKey= new SecretKeySpec(derivedKey, "AES");
		return aesDerivedKey;
	}

}
