//Manvinder Toor
//Cs 380
// file transfer with encryption



import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.Scanner;
import java.util.zip.CRC32;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class FileTransfer{
	public static void main(String[] args) throws Exception{
		String[] _args = Arrays.copyOf(args, args.length);
		//get args
		if (args.length <= 0) {
			System.out.println("must pass 'makekeys' or 'server file port' or 'client file ip port'");
		}
		//if makekeys
		else if(_args[0].compareTo("makekeys") == 0) {
			System.out.println("makekeys");
			makekeys();
			
		//if server
		}else if(_args[0].compareTo("server") == 0) {
			server(_args);
			
		//if client
		}else if(_args[0].compareTo("client") == 0) {
			System.out.println("client");
			client(_args);
		//default
		}else {
			System.out.println("must pass 'makekeys' | 'server' | 'client'");
		}
	}
	private static void makekeys(){
		try {
			//make RSA Key Pair
			KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
			//serialize and put in public.bin and private.bin
			gen.initialize(4096);
			KeyPair keyPair = gen.genKeyPair();
			PrivateKey privateKey = keyPair.getPrivate();
			PublicKey publicKey = keyPair.getPublic();
			try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(new File("public.bin")))) {
				oos.writeObject(publicKey);
			}
			try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(new File("private.bin")))) {
				oos.writeObject(privateKey);
			}
			//exit program
		} catch (NoSuchAlgorithmException | IOException e) {
			e.printStackTrace(System.err);
		}
	}
	private static void server(String[] args) throws Exception{
		Cipher rsa = Cipher.getInstance("RSA");
		Cipher aes = Cipher.getInstance("AES");
		CRC32 crc = new CRC32();
		//arg1 = name of key file
		String privateKeyFile = args[1];
		//arg2 = port number
		int port = Integer.parseInt(args[2]);
		int seqNum = 0;
		int expectedSequence = 0;
		long fileSize = 0;
		int totalChunk = -1;
		boolean readInput = true;
		
		try (ServerSocket serverSocket = new ServerSocket(port)) {
			while (true) {
				//wait for new connection
				Socket socket = serverSocket.accept();
				//input output stream
				ObjectInputStream ois = new ObjectInputStream(socket.getInputStream());
				ObjectOutputStream oos = new ObjectOutputStream(socket.getOutputStream());
				//input
				Message input;
				while (readInput == true) {
					input = (Message)ois.readObject();
					//if client sends disconnect message close connection
					if (input.getType() == MessageType.DISCONNECT) {
						System.out.println("Client disconnected.");
						socket.close();
						readInput = false;
					}
					//if client sends start message
					//prepare for file transfer
					//respond with ack message with seq 0
					//if transfer cannot begin send ack with seq -1
					else if (input.getType() == MessageType.START) {
						StartMessage sm = (StartMessage)input;
						fileSize = sm.getSize();
						byte[] encryptedKey = sm.getEncryptedKey();

						ObjectInputStream privateFile = new ObjectInputStream(new FileInputStream(privateKeyFile));
						PrivateKey privateKey = (PrivateKey)privateFile.readObject();
						
						try {
							rsa.init(Cipher.DECRYPT_MODE, privateKey);
							byte[] decryptedServerKey = rsa.doFinal(encryptedKey);
							seqNum = 0;
							AckMessage ackMessage = new AckMessage(seqNum);
							oos.writeObject(ackMessage);
							SecretKey secretKey = new SecretKeySpec(decryptedServerKey, 0, decryptedServerKey.length,"AES");
							Key key = (Key)secretKey;
							
							ObjectOutputStream serverKeyFile = new ObjectOutputStream(new FileOutputStream(new File("skey.bin")));
							serverKeyFile.writeObject(key);
						} catch(Exception e){
							seqNum = -1;
							AckMessage ackMessage = new AckMessage(seqNum);
							oos.writeObject(ackMessage);
							e.printStackTrace();
						}
					}
					//if client sends stop message
					//discard the file transfer
					//respond with ackmessage and seq -1
					else if (input.getType() == MessageType.STOP) {
						seqNum = -1;
						AckMessage ackMessage = new AckMessage(seqNum);
						oos.writeObject(ackMessage);
					}
					//if client sends Chunk and server initiated file transfer
					//handle chunk
				 	//(a)The Chunk’s sequence number must be the next expected sequence number by the server. 
					//(b) If so, the server should decrypt the data stored in the Chunk using the session key from the transfer initialization step.
					//(c) Next, the server should calculate the CRC32 value for the decrypted data and compare it with the CRC32 value included in the chunk.
					//(d) If these values match and the sequence number of the chunk is the next expected sequence number, the server should accept the chunk by storing the data and incrementing the next expected sequence number. 
					//(e) The server should then respond with an AckMessage with sequence number of the next expected chunk.
					else if (input.getType() == MessageType.CHUNK) {
						Chunk chunk = (Chunk)input;
						int chunkSeq = chunk.getSeq();
						
						if (chunkSeq == expectedSequence) {
							byte[] chunkData = chunk.getData();
							
							ObjectInputStream getSessionKey = new ObjectInputStream(new FileInputStream("skey.bin"));
							Key key = (Key)getSessionKey.readObject();
							aes.init(Cipher.DECRYPT_MODE, key);
							byte[] decryptedChunk = rsa.doFinal(chunkData);
							
							crc.update(decryptedChunk);
							long checkSum = crc.getValue();
							
							if ((int)checkSum == chunk.getCrc()) {
								expectedSequence++;
								
								FileOutputStream fos;
								if (expectedSequence == 1) {
									fos = new FileOutputStream("test2.txt");
									fos.write(decryptedChunk);
								}
								else {
									fos = new FileOutputStream("test2.txt", true);
									fos.write(decryptedChunk);
								}
								
								if (expectedSequence != totalChunk) {
									int chunkSize = decryptedChunk.length;
									totalChunk = (int)Math.ceil(fileSize/(double)chunkSize);
								}
								System.out.println("Chunk received: [" + expectedSequence + "/" + totalChunk + "].");
								
								AckMessage ackMessage;
								if (expectedSequence < totalChunk) {
									ackMessage = new AckMessage(expectedSequence);
									oos.writeObject(ackMessage);
								}
								else {
									System.out.println("Transfer complete.");
									System.out.println("Output path: test2.txt\n");
									fos.close();
									ackMessage = new AckMessage(expectedSequence);
									oos.writeObject(ackMessage);
									totalChunk = -1;
									expectedSequence = 0;
								}
							}
						}
						else {
							AckMessage ackMessage = new AckMessage(expectedSequence);
							oos.writeObject(ackMessage);
						}
					}
					else {
						System.out.println("Error.");
					}
				}
			}
		} catch (Exception e) {
			e.printStackTrace(System.err);
		}
	}
	private static void client(String[] args) throws Exception{
		Cipher rsa = Cipher.getInstance("RSA");
		Cipher aes = Cipher.getInstance("AES");
		CRC32 crc = new CRC32();
		//arg1 = name of keyfile
		String publicKeyFile = args[1];
		//arg2 = host ip
		String host = args[2];
		//arg3 = port number to server
		int port = Integer.parseInt(args[3]);
		boolean run = true;
		
		Socket socket = new Socket(host, port);
		System.out.println("Connected to server: " + host + "/" + socket.getInetAddress().getHostAddress());
		//generate AES session key
		KeyGenerator keyGen = KeyGenerator.getInstance("AES");
		keyGen.init(128);
		SecretKey secretKey = keyGen.generateKey();
		
		byte[] sessionKey = secretKey.getEncoded();
		
		ObjectInputStream publicFile = new ObjectInputStream(new FileInputStream(publicKeyFile));
		PublicKey publicKey = (PublicKey)publicFile.readObject();
		//encrypt the session key using server public key
		rsa.init(Cipher.ENCRYPT_MODE, publicKey);
		byte[] encryptedSessionKey = rsa.doFinal(sessionKey);
		
		Scanner input = new Scanner(System.in);
		ObjectInputStream ois = new ObjectInputStream(socket.getInputStream());
		ObjectOutputStream oos = new ObjectOutputStream(socket.getOutputStream());
		
		while (run == true) {
			boolean fileFound = false;
			String fileName = "";
			FileInputStream fis = null;
			//prompt user to enter the path for a file to transfer
			while (!fileFound) {
				System.out.print("Enter path: ");
				fileName = input.nextLine();
				try {
					fis = new FileInputStream(fileName);
					fileFound = true;
				} catch (FileNotFoundException e) {
					System.out.println("Enter valid filename.");
				}
			}
			
			boolean validSize = false;
			String input2 = "";
			//if the path is valid ask the user to enter the desired chunk size in bytes(default to 1024)
			int chunkSize = 1024;
			
			while (!validSize) {
				System.out.print("Enter chunk size [1024]: ");
				input2 = input.nextLine();
				try {
					chunkSize = Integer.parseInt(input2);
					validSize = true;
				} catch (Exception e) {
					System.out.println("Please enter a valid chunk size (integer).");
				}
			}
			//after accepting the path and chunk size send the server a startmessage
			//contain file name, length and file in bytes, chucnksize and encrypted session key
			StartMessage startMessage = new StartMessage(fileName, encryptedSessionKey, chunkSize);
			oos.writeObject(startMessage);
			
			AckMessage ackMessage = (AckMessage)(ois.readObject());
			int seq = ackMessage.getSeq();

			if (seq == 0) {
				long fileSize = startMessage.getSize();
				int totalChunk = (int)Math.ceil(fileSize/(double)chunkSize);
				
				System.out.println("Sending: " + fileName + ". File size: " + fileSize + ".");
				System.out.println("Sending " + totalChunk + " chunks.");
				
				byte[] fileByteArray = new byte[(int)fileSize];
				
				fis.read(fileByteArray);
				int count = 0;
				int currentChunk = 1;
				//the client should then send chunk with crc32
				
				byte[] chunkData = new byte[chunkSize];
				
				for (int i = 0; i < fileByteArray.length; i++) {
					chunkData[i % (chunkSize)] = fileByteArray[i];
					
					if ((i > 0 && i % (chunkSize) == (chunkSize - 1)) || (i == fileByteArray.length - 1)) {
						byte[] chunkData2;
						if (currentChunk == totalChunk) {
							chunkData2 = Arrays.copyOf(chunkData, i % chunkSize + 1);
						}
						else {
							chunkData2 = Arrays.copyOf(chunkData, chunkData.length);
						}
						
						crc.update(chunkData2);
						long checkSum = crc.getValue();
						
						aes.init(Cipher.ENCRYPT_MODE, secretKey);
						byte[] encryptedChunk = rsa.doFinal(chunkData2);
						
						Chunk chunk = new Chunk(count, encryptedChunk, (int)checkSum);
						oos.writeObject(chunk);
						System.out.println("Chunks completed [" + currentChunk + "/" + totalChunk + "].");
						fis.close();
						
						ackMessage = (AckMessage)ois.readObject();
						seq = ackMessage.getSeq();
						
						if (seq == (count + 1)) {
							count++;
							currentChunk++;
						}
						else {
							i = i + chunkSize;
						}
					}
				}
			}
			
			//disconnect
			run = false;
			DisconnectMessage disconnect = new DisconnectMessage();
			oos.writeObject(disconnect);
			System.out.println("Disconnected from server.");
		}
	}

}