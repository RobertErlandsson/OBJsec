import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;

import javax.crypto.KeyAgreement;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;


public class DiffieHellman {
	
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
		
	public static byte[] sharedSecret(PublicKey publicKey, PrivateKey privateKey){
		try {
            KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH", "BC");
            keyAgreement.doPhase(publicKey, true);
            keyAgreement.init(privateKey); 
            byte[] value = keyAgreement.generateSecret();
            return value;
        } catch (Exception e) {
            return null;
        }
	}
} 

