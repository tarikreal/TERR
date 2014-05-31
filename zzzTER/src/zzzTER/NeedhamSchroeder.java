package zzzTER;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Random;

import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.x509.X509V1CertificateGenerator;

public class NeedhamSchroeder {

	BigInteger na;

	public static byte[] step1nonceAToB(X509Certificate certA, PrivateKey keyA,
			X509Certificate certB, BigInteger nonce) {
		// M3: A --> B: {Na,A}Kb { {Na}Ka', A }Kb
		try {
			CMSSignedData nonceSigned = CMSDataManager.signMessage(certA, keyA,
					nonce.toByteArray());
			byte[] nonceEncrypted = CMSDataManager.encryptMessage(
					nonceSigned.getEncoded(), certB);
			return nonceEncrypted;
		} catch (Exception e) {
			return null;
		} // End try/catch block
	} // End step1nonceAToB

	public static byte[] step2nonceAnonceBToA(X509Certificate certA,
			PrivateKey keyB, BigInteger nonceB, byte[] nonceEncrypted,
			boolean requireValidSig) {
		// M6: B --> A: {Na,Nb}Ka
		try {
			CMSSignedData nonceSigned = new CMSSignedData(
					(byte[]) CMSDataManager
							.decryptMessage(nonceEncrypted, keyB));
			byte[] rawnonceA = (byte[]) CMSDataManager
					.verifySignedMessage(nonceSigned);
			if (rawnonceA == null && requireValidSig) {
				return null;
			} // End if
			byte[] rawnonceB = nonceB.toByteArray();
			byte[] container = new byte[rawnonceA.length + rawnonceB.length];

			System.arraycopy(rawnonceA, 0, container, 0, rawnonceA.length);
			System.arraycopy(rawnonceB, 0, container, rawnonceA.length,
					rawnonceB.length);

			byte[] nonceAnonceBEncrypted = CMSDataManager.encryptMessage(
					container, certA);
			return nonceAnonceBEncrypted;
		} catch (Exception e) {
		} // End try/catch block
		return null;
	} // step2nonceAnonceBToA

	public static BigInteger getnonceAFromStep1(PrivateKey keyB,
			byte[] nonceEncrypted) {
		try {
			CMSSignedData nonceSigned = new CMSSignedData(
					(byte[]) CMSDataManager
							.decryptMessage(nonceEncrypted, keyB));
			byte[] rawnonceA = (byte[]) CMSDataManager
					.verifySignedMessage(nonceSigned);
			return new BigInteger(rawnonceA);
		} catch (Exception e) {
			return null;
		} // try/catch block

	} // End of getnonceAFromStep1

	public static byte[] step3nonceBToB(PrivateKey keyA, X509Certificate certB,
			byte[] dataEncrypted, BigInteger nonceAOrig) {
		try {
			byte[] container = (byte[]) CMSDataManager.decryptMessage(
					dataEncrypted, keyA);
			byte[] nonceA = Arrays.copyOf(container,
					nonceAOrig.toByteArray().length);
			byte[] nonceB = Arrays.copyOfRange(container,
					nonceAOrig.toByteArray().length, container.length);
			if (nonceAOrig.equals(new BigInteger(nonceA))) {
				System.out.println("OK");
				byte[] nonceBEncrypted = CMSDataManager.encryptMessage(nonceB,
						certB);
				return nonceBEncrypted;
			} else
				return null; // return null if the nonce is not equal
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		} // End try/catch block
	} // End of step3nonceBToB

	public static BigInteger getNonceBFromStep2(PrivateKey keyA,
			byte[] dataEncrypted, BigInteger nonceAOrig) {
		try {
			byte[] container = (byte[]) CMSDataManager.decryptMessage(
					dataEncrypted, keyA);
			byte[] nonceB = Arrays.copyOfRange(container,
					nonceAOrig.toByteArray().length, container.length);
			return new BigInteger(nonceB);
		} catch (Exception e) {
			return null;
		} // End of try/catch block
	} // End of getNonceBFromStep2

	public static boolean step3received(PrivateKey keyB, BigInteger nonceBOrig,
			byte[] nonceBEnc) {
		try {
			byte[] nonceB = (byte[]) CMSDataManager.decryptMessage(nonceBEnc,
					keyB);
			if (nonceBOrig.equals(new BigInteger(nonceB))) {
				System.out.println("OK");
				return true;
			} else
				return false;
		} catch (Exception e) {
			return false;
		} // End of try/catch block 
	} // End of step3received

	public static BigInteger generateNonce() {
		/*
		 * Generate a random BigInteger
		 */
		Random randomGenerator = new Random();
		return new BigInteger(53, randomGenerator);
	} // End of generateNonce()

	//
	// public static byte[] generateSessionKey(BigInteger nonceA, BigInteger
	// nonceB) {
	// /*
	// * Generate the session from the two nonce
	// */
	// byte[] rawA = nonceA.toByteArray();
	// byte[] rawB = nonceB.toByteArray();
	// byte[] seed = new byte[rawA.length+rawB.length];
	//
	// System.arraycopy(rawA, 0, seed, 0, rawA.length);
	// System.arraycopy(rawB, 0, seed, rawA.length, rawB.length);
	// return MessageDigestUtils.digest(seed);
	// }
	public static void main(String[] args) throws CertificateEncodingException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, IllegalStateException, SignatureException {
		 Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		NeedhamSchroeder ns;
		SelfSignedX509CertificateGeneratorDemo sf;  
		
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", "BC");
	        keyPairGenerator.initialize(1024, new SecureRandom());

	        KeyPair keyA = keyPairGenerator.generateKeyPair();
	        KeyPair keyB = keyPairGenerator.generateKeyPair();
	        
	        
		X509V1CertificateGenerator certGen = new X509V1CertificateGenerator();
		X509Certificate certA = SelfSignedX509CertificateGeneratorDemo.setCertificateInformation(certGen,keyA); 
		X509Certificate certB = SelfSignedX509CertificateGeneratorDemo.setCertificateInformation(certGen,keyB);
		BigInteger nonce = generateNonce();
		
		System.out.println(nonce);
		
		byte[] nonceEncrypted =NeedhamSchroeder.step1nonceAToB(certA, keyA.getPrivate(), certB, nonce);
		
		System.out.println(nonceEncrypted);
	  //  The public key isn't the same inside the KeyB and CertB  !
		System.out.println(certB.getPublicKey().getEncoded());
		System.out.println(certB.getType());
		System.out.println(keyB.getPublic().getEncoded());
		
	} // End of main()

} // End of NeedhamSchroeder Class
