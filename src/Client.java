import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;


public class Client{
    
    public static void main(String args[]) throws Exception  { 
    	DatagramSocket sockRecive = null;
    	DatagramSocket sockSend = null;
    	int port1 = 4444;  
    	int port2 = 3333;
    	
    	try {
			sockRecive = new DatagramSocket(port1);
			sockSend = new DatagramSocket();
			InetAddress host = InetAddress.getByName("localhost");
			PublicKey publicKey = DiffieHellman.genKeys().getPublic();
			PrivateKey privateKey = DiffieHellman.genKeys().getPrivate();
			sendHello(sockSend, host, port2);
			while(true){
			if(reciveHello(sockRecive)){
				sendPublicKey(sockSend, publicKey, host, port2);
				break;
			}
		}
			while(true){
				if(reciveServerKey(sockRecive)!=null){
					break;
				}
			}
    	}catch (IOException e){
    		System.err.println("IOException " + e);
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
    
    public static boolean reciveHello(DatagramSocket sockRecive){
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
    
    public static void sendPublicKey(DatagramSocket sockSend, PublicKey pubKey, InetAddress host, int port2){
    	byte[] publicKey = pubKey.getEncoded();  // byte
    		
    	try {
			sockSend.send(new DatagramPacket(publicKey, publicKey.length, host, port2));
		} catch (IOException e) {
			e.printStackTrace();
		}
    	
    }
   
    public static PublicKey reciveServerKey(DatagramSocket sockRecive){
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
