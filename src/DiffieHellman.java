import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;


public class DiffieHellman {
	public static byte[] S = new SecureRandom().generateSeed(16);
	
	public static KeyPair genKeys() {
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("prime192v1");
		KeyPairGenerator g;
		
		try{
		g = KeyPairGenerator.getInstance("ECDSA", "BC");
		g.initialize(ecSpec);
		KeyPair pair = g.generateKeyPair();
		return pair;
		
		}catch(Exception e){
			return null;
		}
	}
		
	public SecretKey sharedSecret(PublicKey publicKey, PrivateKey privateKey){
		try {
            KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH", "BC");
            keyAgreement.doPhase(publicKey, true);
            keyAgreement.init(privateKey); 
            byte[] value = keyAgreement.generateSecret();
            SecretKey secret = new SecretKeySpec(value,0,16,"AES");
            return secret;
        } catch (Exception e) {
            return null;
        }
	}
} 

