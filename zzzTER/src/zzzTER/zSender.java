package zzzTER;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.rmi.server.SkeletonMismatchException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;

public class zSender {
	public static Socket socket;

	public static void main(String[] args) throws InterruptedException {
		try {
			Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
			try {
				String host = "localhost";
				InetAddress address = InetAddress.getByName(host);
				int port = 25000;
				socket = new Socket(address, port);
				
				KeyPairGenerator kpg = KeyPairGenerator
						.getInstance("RSA", "BC");
				KeyPair kp = kpg.generateKeyPair();

				/** OuputStreams **/
				DataOutputStream dos = new DataOutputStream(
						socket.getOutputStream());

				/** InputStreams **/
				//
				DataInputStream dis = new DataInputStream(
						socket.getInputStream());

				/** KeyExchange **/

				/** Send public key **/
                 
				byte[] publickey = kp.getPublic().getEncoded();
				
				
				sendPublicKeybyDOS(dos, publickey);
           
				/** Receive public key from the remote **/
				
				
				byte[] remotePublicKey = receivePublicKeybyDIS(dis);
			socket.setKeepAlive(true);
			} catch (NoSuchAlgorithmException nsae) {
				nsae.printStackTrace();
			} catch (NoSuchProviderException nspe) {
				nspe.printStackTrace();
			} // End of try/catch block
		} catch (IOException ioe) {
			ioe.printStackTrace();
		} // End of try/catch
	} // End of main()

	

	

	public static byte[] cipherMode(byte[] input, Cipher cipher,
			KeyPair encryptionKey) throws NoSuchAlgorithmException,
			NoSuchProviderException, NoSuchPaddingException,
			IllegalBlockSizeException, ShortBufferException,
			BadPaddingException, InvalidKeyException {
		cipher.init(Cipher.ENCRYPT_MODE, encryptionKey.getPublic());
		byte[] cipherText = new byte[cipher.getOutputSize(input.length)];
		int ctLength = cipher.update(input, 0, input.length, cipherText, 0);
		ctLength += cipher.doFinal(cipherText, ctLength);
		String temp = new String(cipherText);
		return cipherText;
	} // End ofcipherMode()

	public static byte[] decipheredMode(byte[] cipherText, Cipher cipher,
			KeyPair encryptionKey) throws ShortBufferException,
			NoSuchAlgorithmException, NoSuchProviderException,
			NoSuchPaddingException, InvalidKeyException,
			IllegalBlockSizeException, BadPaddingException {

		cipher.init(Cipher.DECRYPT_MODE, encryptionKey.getPrivate());
		byte[] plainText = new byte[cipher.getOutputSize(cipherText.length)];
		int ctLength = cipher.update(cipherText, 0, cipherText.length,
				cipherText, 0);
		int ptLength = cipher.update(cipherText, 0, ctLength, plainText, 0);
		ptLength += cipher.doFinal(plainText, ptLength);
		return plainText;
	} // End of decipheredMode

	public static byte[] makeFormat(byte[] decipheredNumber) {
		int length = 0;
		for (int i = 0; i < decipheredNumber.length; i++) {
			if ((int) decipheredNumber[i] != 0) {
				length++;
			} // End if
		} // End for
		byte[] newDecipheredNumber = new byte[length];
		for (int j = 0; j < newDecipheredNumber.length; j++) {
			newDecipheredNumber[j] = decipheredNumber[j];
		} // End for

		return newDecipheredNumber;
	} // End of makeFormat()

	public static void sendPublicKeybyDOS(DataOutputStream dos, byte[] key) {
		DateFormat dateFormat = new SimpleDateFormat("yyyy/MM/dd HH:mm:ss");
		Date date = new Date();
		try {
			// StringBuilder sb = new StringBuilder("10");
			/** Send the message **/
			String SendMessage = new String(key);
					
			dos.writeUTF(SendMessage);

			System.out.println("Public key sent at ... " + SendMessage + "   "
					+ dateFormat.format(date) + "Length of the message"
					+ SendMessage.length());
			System.out.println(socket.isClosed());
			dos.flush();
			
		} catch (IOException e) {
			e.printStackTrace();
		}// End of try/catch block

	} // End of sendPublicKeybyDOS

	public static byte[] receivePublicKeybyDIS(DataInputStream dis)
			throws IOException {
		/** Date Format **/
		DateFormat dateFormat = new SimpleDateFormat("yyyy/MM/dd HH:mm:ss");
		Date date = new Date();
		System.out.println(socket.isClosed());
		String received = dis.readUTF();
		/** Receive the message **/

		System.out.println("Message received : " + received + " at ... "
				+ dateFormat.format(date) + " \n" + received);
		return received.getBytes();

	} // End of receivePublicKey

} // End of zSender
