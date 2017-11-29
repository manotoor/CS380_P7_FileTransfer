public class FileTransfer{
	public static void main(String[] args){
		//get args
		//if makekeys
			//do makekeys(args)
		//if client
			//do client(args)
		//if server
			//do server(args)
	}
	private static void makekeys(String[] args){
		//make RSA Key Pair
		//serialize and put in public.bin and private.bin
		//exit program
	}
	private static void server(String[] args){
		//arg1 = name of key file
		//arg2 = port number
		//if client sends disconnect message close connection
		//and wait for new connection

		//if client sends start message
			//prepare for file transfer
			//respond with ack message with seq 0
			//if transfer cannot begin send ack with seq -1

		//if client sends stop message
			//discard the file transfer
			//respond with ackmessage and seq -1

		//if client sends Chunk and server initiated file transfer
			//handle chunk
		 	//(a)The Chunk’s sequence number must be the next expected sequence number by the server. 
			//(b) If so, the server should decrypt the data stored in the Chunk using the session key from the transfer initialization step.
			//(c) Next, the server should calculate the CRC32 value for the decrypted data and compare it with the CRC32 value included in the chunk.
			//(d) If these values match and the sequence number of the chunk is the next expected sequence number, the server should accept the chunk by storing the data and incrementing the next expected sequence number. (e) The server should then respond with an AckMessage with sequence number of the next expected chunk.

	}
	private static void client(String[] args){
		//arg1 = name of keyfile
		//arg2 = host ip
		//arg3 = port number to server
		//generate AES session key
		//encrypt the session key using server public key
		//prompt user to enter the path for a file to transfer
		//if the path is valid ask the user to enter the desired chunk size in bytes(default to 1024)
		//after accepting the path and chunk size send the server a startmessage
		//contain file name, length and file in bytes, chucnksize and encrypted session key
		//the client should then send chunk with crc32
		//send final ack
		//disconnect
	}
}