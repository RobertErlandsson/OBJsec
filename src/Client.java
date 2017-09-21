import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

public class Client {
	private static Key derivedAESKey;

	public static void main(String[] args) throws Exception{
		DatagramSocket sockReceive = null;
		DatagramSocket sockSend = null;
		int port1 = 4446;  
		int port2 = 3335;
		PublicKey publicKeyClient = DiffieHellman.genKeys().getPublic();
		PrivateKey privateKey = DiffieHellman.genKeys().getPrivate();
		sockReceive = new DatagramSocket(port1);
		sockSend = new DatagramSocket();  
		PublicKey publicKeyServer;

		try{
			InetAddress host = InetAddress.getByName("localhost");	
			sendHello(sockSend, host, port2);
			while(true){
				if(receiveHello(sockReceive)){
					break;
				}
			}
			System.out.println("Sending public key to server.");
			sendPublicKey(sockSend, publicKeyClient, host, port2);
			while (true) {
				if ((publicKeyServer = receiveServerKey(sockReceive)) != null) {
					System.out.println("got public key from server.");
					break;
				}
			}
			System.out.println(publicKeyServer);
			System.out.println(publicKeyClient);
			System.out.println(privateKey);
			derivedAESKey =	utility.deriveAESKeyClient(publicKeyServer, publicKeyClient ,privateKey);
			System.out.println("Data transfer ready");
			System.out.println(derivedAESKey);

			requestObject(sockSend, host, port2, "hej");
			receiveObject(derivedAESKey, sockReceive);

		}catch (IOException e){
			System.err.println("IOException " + e);
		}		
	}
	public static void receiveObject(Key derivedAESkey, DatagramSocket sockReceive) throws Exception{
		byte[] recvBuf = new byte[5000];
		DatagramPacket packet = new DatagramPacket(recvBuf, recvBuf.length);
		sockReceive.receive(packet);
		ByteArrayInputStream byteStream = new ByteArrayInputStream(recvBuf);
		ObjectInputStream is = new ObjectInputStream(new BufferedInputStream(byteStream));
		SecureObject decObj = (SecureObject) is.readObject();
		is.close();

		String decHeader = SecureObject.decryptString(derivedAESkey ,decObj.getHeader());
		String decPayload = SecureObject.decryptString(derivedAESkey ,decObj.getPayload());

		System.out.println("Decrypted Objectify...");
		System.out.println("header: " + decHeader);
		System.out.println("payload: " + decPayload);
		System.out.println("name: " + SecureObject.decryptString(derivedAESkey ,decObj.getName()));
		System.out.println("Integrity: " + decObj.getIntegrity());

		if(decObj.getIntegrity().equals(SecureObject.createHMAC("HmacSHA512", "holy", decHeader + decPayload))) {
			System.out.println("SecureObject verified");
		} else {
			System.out.println("INTEGRITY UNVERIFIED");
		}
	}

	public static void sendHello(DatagramSocket sockSend, InetAddress host, int port2){
		byte[] helloServer = "Hello Server".getBytes();
		DatagramPacket cHello = new DatagramPacket(helloServer, helloServer.length, host, port2);
		try {
			sockSend.send(cHello);
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	public static boolean receiveHello(DatagramSocket sockRecive){
		byte[] buffer = new byte[1024];
		DatagramPacket incoming = new DatagramPacket(buffer, buffer.length);
		try {
			sockRecive.receive(incoming);
		} catch (IOException e) {
			e.printStackTrace();
			return false;
		}
		byte[] data = incoming.getData();
		String string = new String(data, 0, incoming.getLength());

		if (string.equals("Hello Client")) {
			System.out.println("SUCCESS");
			return true;
		} 
		return false;

	}

	public static void requestObject(DatagramSocket sockSend, InetAddress host,
			int port2,String name){
		byte[] byteRequest = name.getBytes();
		DatagramPacket request = new DatagramPacket(byteRequest, byteRequest.length, host, port2);
		try {
			sockSend.send(request);
		} catch (IOException e) {
			e.printStackTrace();
		}	
	}

	public static void sendPublicKey(DatagramSocket sockSend, PublicKey pubKey, InetAddress host, int port2){
		byte[] publicKey = pubKey.getEncoded();  // byte

		try {
			sockSend.send(new DatagramPacket(publicKey, publicKey.length, host, port2));
		} catch (IOException e) {
			e.printStackTrace();
		}

	}

	public static PublicKey receiveServerKey(DatagramSocket sockRecive){
		byte[] buffer = new byte[1024];
		DatagramPacket incoming = new DatagramPacket(buffer, buffer.length);

		try {
			sockRecive.receive(incoming);
		} catch (IOException e) {
			e.printStackTrace();
		}
		byte[] data = incoming.getData();
		byte[] serverKeyByte = new byte[incoming.getLength()];

		System.arraycopy(data, 0, serverKeyByte,0, incoming.getLength());

		PublicKey publicKeyServer = Server.getPublicKeyFromByte(serverKeyByte);

		if(publicKeyServer != null){
			return publicKeyServer;
		}else{
			return null;
		}
	}

	public static PublicKey getPublicKeyFromByte(byte[] serverKeyByte){
		try {
			KeyFactory keyfactor = KeyFactory.getInstance("ECDSA");
			PublicKey publicKey = keyfactor.generatePublic(new X509EncodedKeySpec(serverKeyByte));
			return publicKey;		
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			e.printStackTrace();
		}
		return null; 
	}
}
