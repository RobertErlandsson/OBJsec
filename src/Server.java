import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.io.UnsupportedEncodingException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class Server {
	private static Key derivedAESKey;
	
	public static void main(String[] args) throws Exception {

		DatagramSocket sockReceive = null;
		DatagramSocket sockSend = null;
		int port1 = 3335;
		int port2 = 4446;
		PublicKey publicKeyServer = DiffieHellman.genKeys().getPublic();
		PrivateKey privateKey = DiffieHellman.genKeys().getPrivate();
		PublicKey publicKeyClient;
		ArrayList<SecureObject> objectList = new ArrayList<SecureObject>();
		objectList.add(new SecureObject("header", "this is the payload", "Object1"));
		objectList.add(new SecureObject("header", "this is another payload", "Object2"));
		try {
			sockReceive = new DatagramSocket(port1);
			sockSend = new DatagramSocket();
			InetAddress host = InetAddress.getByName("localhost");
			while (true) {
				System.out.println("Waiting for client");
				if (receiveHello(sockReceive)) {
					break;
				}
			}
			sendHello(sockSend, host, port2);
			while (true) {
				System.out.println("Waiting for clientKEY");
				if ((publicKeyClient = receiveClientKey(sockReceive)) != null) {
					sendPublicKey(sockSend, publicKeyServer, host, port2);
					break;
				}

			}
			
			System.out.println(publicKeyServer);
			System.out.println(publicKeyClient);
			System.out.println(privateKey);
			derivedAESKey = utility.deriveAESKeyServer(publicKeyServer, publicKeyClient, privateKey);
			System.out.println("Data transfer ready");
			System.out.println(derivedAESKey);

			waitingForRequest(sockReceive, derivedAESKey, objectList, host, port2, sockSend);
					
		} catch (IOException e) {
			System.err.println("IOException " + e);
		}
		
		}
	

	public static void sendObject(Key derivedAESkey, int index, ArrayList<SecureObject> objectList,
			InetAddress host, int port, DatagramSocket sockSend) throws Exception{
		

		SecureObject asdf = objectList.get(index);
		SecureObject encObj = new SecureObject(SecureObject.encryptString(derivedAESkey,asdf.getHeader()), SecureObject.encryptString(derivedAESkey, asdf.getPayload()), SecureObject.encryptString(derivedAESkey,asdf.getName()));
		encObj.setIntegrity(SecureObject.createHMAC("HmacSHA512", "holy", asdf.getHeader() + asdf.getPayload()));
		
		ByteArrayOutputStream byteStream = new ByteArrayOutputStream(5000);
		ObjectOutputStream oostream = new ObjectOutputStream(new BufferedOutputStream(byteStream));
		oostream.flush();
		oostream.writeObject(encObj);
		oostream.flush();
		byte[] sendBuf = byteStream.toByteArray();
		DatagramPacket packet = new DatagramPacket(sendBuf, sendBuf.length, host, port);
		//int byteCount = packet.getLength();
		sockSend.send(packet);
		oostream.close();
	}
	
	private static void waitingForRequest(DatagramSocket sockReceive,Key derivedAESkey,
			ArrayList<SecureObject> objectList,InetAddress host, int port, DatagramSocket sockSend) throws Exception {
		while(true){
		byte[] buffer = new byte[1024];
		int index;
		DatagramPacket incoming = new DatagramPacket(buffer, buffer.length);
		try {
			sockReceive.receive(incoming);
		} catch (IOException e) {
			e.printStackTrace();
		}
		byte[] data = incoming.getData();
		String string = new String(data, 0, incoming.getLength());
		if(string.equals("quit")){
			System.out.println("Server shuting down.");
			break;
		}else{ 
			sendObject(derivedAESKey, 0, objectList, host, port, sockSend);
		}
		
			
		}
	}
		
	

	public static boolean receiveHello(DatagramSocket sockReceive) {
		byte[] buffer = new byte[1024];
		DatagramPacket incoming = new DatagramPacket(buffer, buffer.length);
		try {
			sockReceive.receive(incoming);
		} catch (IOException e) {
			e.printStackTrace();
			return false;
		}
		byte[] data = incoming.getData();
		String string = new String(data, 0, incoming.getLength());

		if (string.equals("Hello Server")) {
			System.out.println("SUCCESS");
			return true;
		}
		return false;

	}

	public static void sendHello(DatagramSocket sockSend, InetAddress host, int port2) {
		byte[] helloClient = "Hello Client".getBytes();
		DatagramPacket cHello = new DatagramPacket(helloClient, helloClient.length, host, port2);
		try {
			sockSend.send(cHello);
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	public static void sendPublicKey(DatagramSocket sockSend, PublicKey pubKey, InetAddress host, int runPort) {
		byte[] publicKey = pubKey.getEncoded(); // byte

		try {
			sockSend.send(new DatagramPacket(publicKey, publicKey.length, host, runPort));
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	public static PublicKey receiveClientKey(DatagramSocket sockReceive) {
		byte[] buffer = new byte[1024];
		DatagramPacket incoming = new DatagramPacket(buffer, buffer.length);

		try {
			sockReceive.receive(incoming);
		} catch (IOException e) {
			e.printStackTrace();
		}
		byte[] data = incoming.getData();
		byte[] clientKeyByte = new byte[incoming.getLength()];

		System.arraycopy(data, 0, clientKeyByte, 0, incoming.getLength());

		PublicKey publicKeyClient = Server.getPublicKeyFromByte(clientKeyByte);

		if (publicKeyClient != null) {
			return publicKeyClient;
		} else {
			return null;
		}

	}

	public static PublicKey getPublicKeyFromByte(byte[] serverKeyByte) {
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
