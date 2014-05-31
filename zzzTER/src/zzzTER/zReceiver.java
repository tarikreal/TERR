package zzzTER;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.net.ServerSocket;
import java.net.Socket;
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
import javax.sound.midi.Receiver;

public class zReceiver {
	public static Socket socket;
	public static ServerSocket serverSocket;

	public static void main(String[] args) {
		int port = 25000;
		try {
			Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
			/** Sockets and server Sockets **/

			serverSocket = new ServerSocket(port);
			System.out.println("Receiver waiting on " + port);
			socket = serverSocket.accept();

			/********************************/

			/** OuputStreams **/
			OutputStream os = socket.getOutputStream();
			OutputStreamWriter osw = new OutputStreamWriter(os);
			BufferedWriter bw = new BufferedWriter(osw);

			/** InputStreams **/

			InputStream is = socket.getInputStream();
			InputStreamReader isw = new InputStreamReader(is);
			BufferedReader br = new BufferedReader(isw);
			
			/** Creating keys **/
			KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "BC");
			KeyPair kp = kpg.generateKeyPair();
			byte[] key = kp.getPublic().getEncoded();
			/** Key exchange **/
			// boolean exchange = false;

			// while (exchange = false) {
			/** Receive public key **/
			byte[] remotePublicKey = receivePublicKey(br);
			Thread.sleep(1000);
			// exchange = true;
			// } // End while
			/** Send public Key **/
			sendPublicKey(bw, remotePublicKey);

			System.out
					.println("I've received the public key righ now, i'm willing to send you mine");

			sendPublicKey(bw, remotePublicKey);
		} catch (NoSuchAlgorithmException nsae) {
			nsae.printStackTrace();
		} catch (NoSuchProviderException nspe) {
			nspe.printStackTrace();
		} catch (IOException io) {
			io.printStackTrace();
		} catch (InterruptedException ie) {
			ie.printStackTrace();
		} // End of try/catch block

	} // End of main()

	public static void sendPublicKey(BufferedWriter bw, byte[] key) {
		DateFormat dateFormat = new SimpleDateFormat("yyyy/MM/dd HH:mm:ss");
		Date date = new Date();
		try {
			// StringBuilder sb = new StringBuilder("10");
			/** Send the message **/
			bw.write(new String(key) + "\n" + System.lineSeparator());
			bw.flush();
			System.out
					.println("Message sent at ... " + dateFormat.format(date));
		} catch (IOException e) {
			e.printStackTrace();
		} // End of try/catch block
	} // End of sendPublicKey

	public static byte[] receivePublicKey(BufferedReader br) throws IOException {
		/** Date Format **/
		DateFormat dateFormat = new SimpleDateFormat("yyyy/MM/dd HH:mm:ss");
		Date date = new Date();
		StringBuilder sb = new StringBuilder();
		
		String received = br.readLine();
		received = new String(sb);
		/** Receive the message **/
		System.out.println("Message received : " + br.readLine() + " at ... "
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

} // End of zReceiver
