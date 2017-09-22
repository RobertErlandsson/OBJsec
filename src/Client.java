import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.security.Key;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

public class Client {
	private static Key derivedAESKey;

	public static void main(String[] args) throws Exception {
		DatagramSocket sockReceive = null;
		DatagramSocket sockSend = null;
		int port1 = 4446;
		int port2 = 3335;
		KeyPair key = DiffieHellman.genKeys();
		PublicKey publicKey = key.getPublic();
		PrivateKey privateKey = key.getPrivate();
		sockReceive = new DatagramSocket(port1);
		sockSend = new DatagramSocket();
		PublicKey otherPublicKey;

		try {
			InetAddress host = InetAddress.getByName("localhost");
			sendHello(sockSend, host, port2);
			while (true) {
				if (receiveHello(sockReceive)) {
					break;
				}
			}
			System.out.println("Sending public key to server.");
			DiffieHellman.sendPublicKey(sockSend, publicKey, host, port2);
			while (true) {
				if ((otherPublicKey = DiffieHellman.receiveOtherPublicKey(sockReceive)) != null) {
					System.out.println("Received public key from server.");
					break;
				}
			}
			derivedAESKey = DiffieHellman.deriveAESKey(publicKey, otherPublicKey, privateKey);
			System.out.println("Data transfer ready");

			requestObject(sockSend, host, port2, "hej");
			receiveObject(derivedAESKey, sockReceive);

		} catch (IOException e) {
			System.err.println("IOException " + e);
		}
	}

	public static void receiveObject(Key derivedAESkey, DatagramSocket sockReceive) throws Exception {
		byte[] recvBuf = new byte[5000];
		DatagramPacket packet = new DatagramPacket(recvBuf, recvBuf.length);
		sockReceive.receive(packet);
		ByteArrayInputStream byteStream = new ByteArrayInputStream(recvBuf);
		ObjectInputStream is = new ObjectInputStream(new BufferedInputStream(byteStream));
		SecureObject decObj = (SecureObject) is.readObject();
		is.close();

		String decHeader = SecureObject.decryptString(derivedAESkey, decObj.getHeader());
		String decPayload = SecureObject.decryptString(derivedAESkey, decObj.getPayload());

		System.out.println("Decrypted Objectify...");
		System.out.println("header: " + decHeader);
		System.out.println("payload: " + decPayload);
		System.out.println("name: " + SecureObject.decryptString(derivedAESkey, decObj.getName()));
		System.out.println("Integrity: " + decObj.getIntegrity());

		if (decObj.getIntegrity().equals(SecureObject.createHMAC("HmacSHA512", "holy", decHeader + decPayload))) {
			System.out.println("SecureObject verified");
		} else {
			System.out.println("INTEGRITY UNVERIFIED");
		}
	}

	public static void sendHello(DatagramSocket sockSend, InetAddress host, int port2) {
		byte[] helloServer = "Hello Server".getBytes();
		DatagramPacket cHello = new DatagramPacket(helloServer, helloServer.length, host, port2);
		try {
			sockSend.send(cHello);
		} catch (IOException e) {
			e.printStackTrace();
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

		if (string.equals("Hello Client")) {
			System.out.println("SUCCESS");
			return true;
		}
		return false;

	}

	public static void requestObject(DatagramSocket sockSend, InetAddress host, int port2, String name) {
		byte[] byteRequest = name.getBytes();
		DatagramPacket request = new DatagramPacket(byteRequest, byteRequest.length, host, port2);
		try {
			sockSend.send(request);
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

}
