package zzzTER;

import java.io.BufferedReader;
import java.io.BufferedWriter;
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

	public static void main(String[] args) {
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
				OutputStream os = socket.getOutputStream();
				OutputStreamWriter osw = new OutputStreamWriter(os);
				BufferedWriter bw = new BufferedWriter(osw);

				/** InputStreams **/
				InputStream is = socket.getInputStream();
				InputStreamReader isw = new InputStreamReader(is);
				BufferedReader br = new BufferedReader(isw);

				/** KeyExchange **/

				/** Send public key **/

				byte[] publickey = kp.getPublic().getEncoded();
				sendPublicKey(bw,publickey);

				/** Receive public key from the remote **/
				byte[] remotePublicKey = receivePublicKey(br);
				
				
				
				
			} catch (NoSuchAlgorithmException nsae) {
				nsae.printStackTrace();
			} catch (NoSuchProviderException nspe) {
				nspe.printStackTrace();
			} // End of try/catch block
		} catch (IOException ioe) {
			ioe.printStackTrace();
		} // End of try/catch
	} // End of main()

	public static void sendPublicKey(BufferedWriter bw,
			byte[] key) {
		DateFormat dateFormat = new SimpleDateFormat("yyyy/MM/dd HH:mm:ss");
		Date date = new Date();
		try {
			// StringBuilder sb = new StringBuilder("10");
			/** Send the message **/
			String SendMessage = new String(key)+System.getProperty(System.lineSeparator());
			bw.write(SendMessage);
			
			
			System.out.println("Public key sent at ... "+SendMessage
					+"   "+ dateFormat.format(date)+ "Length of the message" + SendMessage.length());
			bw.flush();
			
		} catch (IOException e) {
			e.printStackTrace(); 
		}// End of try/catch block
		
	} // End of sendPublicKey

	public static byte[] receivePublicKey(BufferedReader br) throws IOException {
		/** Date Format **/
		DateFormat dateFormat = new SimpleDateFormat("yyyy/MM/dd HH:mm:ss");
		Date date = new Date();
		StringBuilder sb = new StringBuilder();
		String received= br.readLine();
		/** Receive the message **/
		
		System.out.println("Message received : " + received + " at ... " 
				+ dateFormat.format(date));
		return received.getBytes();

	} // End of receivePublicKey

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
	} // End of cipherMode()

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


} // End of zSender
