import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.security.Key;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;

public class Server {
	private static Key derivedAESKey;

	public static void main(String[] args) throws Exception {

		DatagramSocket sockReceive = null;
		DatagramSocket sockSend = null;
		int port1 = 3335;
		int port2 = 4446;
		KeyPair key = DiffieHellman.genKeys();
		PublicKey publicKey = key.getPublic();
		PrivateKey privateKey = key.getPrivate();
		PublicKey otherPublicKey;
		ArrayList<SecureObject> objectList = new ArrayList<SecureObject>();
		objectList.add(new SecureObject("header", "this is the payload", "Object1"));
		objectList.add(new SecureObject("header", "this is another payload", "Object2"));
		try {
			sockReceive = new DatagramSocket(port1);
			sockSend = new DatagramSocket();
			InetAddress host = InetAddress.getByName("localhost");
			while (true) {
				System.out.println("Waiting for client to connect.");
				if (receiveHello(sockReceive)) {
					break;
				}
			}
			sendHello(sockSend, host, port2);
			while (true) {
				System.out.println("Waiting to receive client public key.");
				if ((otherPublicKey = DiffieHellman.receiveOtherPublicKey(sockReceive)) != null) {
					DiffieHellman.sendPublicKey(sockSend, publicKey, host, port2);
					System.out.println("Sending public key to client.");
					break;
				}

			}

			derivedAESKey = DiffieHellman.deriveAESKey(publicKey, otherPublicKey, privateKey);
			System.out.println("Data transfer ready");

			waitingForRequest(sockReceive, derivedAESKey, objectList, host, port2, sockSend);
			
		} catch (IOException e) {
			System.err.println("IOException " + e);
		}

	}

	public static void sendObject(Key derivedAESkey, int index, ArrayList<SecureObject> objectList,
			InetAddress host, int port, DatagramSocket sockSend) throws Exception{
		
		SecureObject temp = objectList.get(index);
		SecureObject encObj = new SecureObject(SecureObject.encryptString(derivedAESkey,temp.getHeader()), SecureObject.encryptString(derivedAESkey, temp.getPayload()), SecureObject.encryptString(derivedAESkey,temp.getName()));
		encObj.setIntegrity(SecureObject.createHMAC("HmacSHA512", "holy", temp.getHeader() + temp.getPayload()));

		ByteArrayOutputStream byteStream = new ByteArrayOutputStream(5000);
		ObjectOutputStream oostream = new ObjectOutputStream(new BufferedOutputStream(byteStream));
		oostream.flush();
		oostream.writeObject(encObj);
		oostream.flush();
		byte[] sendBuf = byteStream.toByteArray();
		DatagramPacket packet = new DatagramPacket(sendBuf, sendBuf.length, host, port);
		sockSend.send(packet);
		oostream.close();
		System.out.println("Data sent.");
	}

	private static void waitingForRequest(DatagramSocket sockReceive,Key derivedAESkey,
			ArrayList<SecureObject> objectList,InetAddress host, int port, DatagramSocket sockSend) throws Exception {
		while(true){
			byte[] buffer = new byte[1024];
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

}
