
public class Main {
	
	public static void main(String[] args) throws Exception{
		Server server = new Server();
		Client client = new Client();
		
		client.handshake();
		server.handshake();
		
		
		
	}

}
