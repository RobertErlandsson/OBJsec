import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

public class Server {

	public static void main(String[] args) throws Exception {

		DatagramSocket sockReceive = null;
		DatagramSocket sockSend = null;
		int port1 = 3333;
		int port2 = 4444;
		PublicKey publicKey = DiffieHellman.genKeys().getPublic();
		PrivateKey privateKey = DiffieHellman.genKeys().getPrivate();
		PublicKey publicKeyClient;

		try {
			sockReceive = new DatagramSocket(port1);
			sockSend = new DatagramSocket();
			InetAddress host = InetAddress.getByName("localhost");
			while (true) {
				if (receiveHello(sockReceive)) {
					break;
				}
			}
			sendHello(sockSend, host, port2);
			while (true) {
				if ((publicKeyClient = receiveClientKey(sockReceive)) != null) {
					sendPublicKey(sockSend, publicKey, host, port2);
					break;
				}

			}
			utility.derivedAESKey(publicKey, publicKeyClient, privateKey);

		} catch (IOException e) {
			System.err.println("IOException " + e);
		}
		
		while(true){
			if(waitingForRequest(sockReceive)){
				break;
			}
		}
	}

	private static boolean waitingForRequest(DatagramSocket sockReceive) {
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

		if (string.equals()) { //Kolla om name(string) objekt finns sparat.
 			System.out.println("SUCCESS");
			return true;
		}
		return false;
		
		
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
