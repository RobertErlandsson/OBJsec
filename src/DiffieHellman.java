import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;

import javax.crypto.KeyAgreement;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;

public class DiffieHellman {

	public static KeyPair genKeys() throws Exception {
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("prime192v1");
		KeyPairGenerator g;
		SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG", "SUN"); 
		try {
			g = KeyPairGenerator.getInstance("ECDSA", "BC");
			g.initialize(ecSpec, secureRandom);
			KeyPair pair = g.generateKeyPair();
			return pair;

		} catch (Exception e) {
			return null;
		}
	}

	public static byte[] sharedSecret(PublicKey publicKey, PrivateKey privateKey) {
		try {
			KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH", "BC");
			keyAgreement.init(privateKey);
			keyAgreement.doPhase(publicKey, true);
			byte[] value = keyAgreement.generateSecret();
			System.out.println("shared secret: " + value);
			return value;
		} catch (Exception e) {
			return null;
		}
	}
}
