package backend;

import java.io.*;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.interfaces.*;
import java.util.Calendar;
import java.util.Date;
import java.util.Scanner;
import java.io.FileWriter;
import java.io.FileReader;
import java.io.BufferedReader;
import java.io.IOException;
//import java.util.LinkedList;
import java.math.BigInteger;
import java.security.spec.*;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import org.jmrtd.cert.*;
import org.bouncycastle.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.ejbca.cvc.AccessRightEnum;
import org.ejbca.cvc.AccessRightSignTermEnum;
import org.ejbca.cvc.AccessRights;
import org.ejbca.cvc.AuthorizationRole;
import org.ejbca.cvc.AuthorizationRoleEnum;
import org.ejbca.cvc.CAReferenceField;
import org.ejbca.cvc.CVCertificate;
import org.ejbca.cvc.CVCertificateBody;
import org.ejbca.cvc.CertificateGenerator;
//import org.ejbca.cvc.*;
//import org.ejbca.cvc.CVCAuthorizationTemplate;
//import org.ejbca.cvc.CardVerifiableCertificate;
import org.ejbca.cvc.HolderReferenceField;

@SuppressWarnings("unused")
public class Backend implements GlobVarBE {

	final protected static char[] hexArray = "0123456789ABCDEF".toCharArray();
	//TODO: List of revoked certificates
	//TODO: List of IDs associated with each terminal and card  --> Request from personalisation terminal? 
	//TODO: List of revoked petrol cards

	public Backend() {
		
	}
	
	/* For every transaction this method is called. 
	 * Verification will be done if the card and terminal are on the CRL
	 * 		IF YES: transaction should be stopped and entry should be logged?
	 * 		IF NOT: continue transaction
	 */
	

	public static boolean isCertificateValid(String tag, int serialNr, int allowance, CardVerifiableCertificate cert){
		try {
			Date dateRevoke;
			byte[] signature = cert.getSignature();

	//		cert.getAuthorityReference();
			return false;
		} catch (Exception e){
			System.out.println("Error in validity checking:" + e.getMessage());
			return false;
		}
		
		// verify if card is on CRL list
		//verify if Cert is signed by private key.
		// verify if date of certificate is still valid
	}
	/* Purpose is to convert signature to a full length string, otherwise you get garbage. */
	public static String bytesToHex(byte[] bytes) {
	    char[] hexChars = new char[bytes.length * 2];
	    for ( int j = 0; j < bytes.length; j++ ) {
	        int v = bytes[j] & 0xFF;
	        hexChars[j * 2] = hexArray[v >>> 4];
	        hexChars[j * 2 + 1] = hexArray[v & 0x0F];
	    }
	    return new String(hexChars);
	}
	
	/* isOnCRL checks whether a certain certificate is on the Certificate Revocation List
	 * 
	 * CRL consists of:
	 * Tag (C or T), C = Card T = Terminal
	 * id = ID number of card or terminal
	 * date-time of revocation, so current date
	 * allowance before revocation
	 * Certificate hash
	 * 
	 * @param tagkey, provider, cert, cert_ca
	 * @return
	 */
	public boolean isOnCRL(KeyPair tagKey, BouncyCastleProvider provider, CVCertificate cert, CVCertificate cert_ca) throws NoSuchFieldException{
		String holderRef = cert.getCertificateBody().getHolderReference().getConcatenated();
		Date validFrom = cert.getCertificateBody().getValidFrom();
		Date validTo = cert.getCertificateBody().getValidTo();
		
		byte[] signature = cert.getSignature();
		String hash = bytesToHex(signature);
		
		try {
			String line;
			BufferedReader buffer = new BufferedReader(new FileReader(CRL_FILE));
			Boolean found = false;
				
			 while((line = buffer.readLine()) != null) {
				 System.out.println("line starts here:");
				 System.out.println( line);
				 if(line.indexOf("20230E5C1F76CE19") != -1) {
					 found = true;			 
					 break;
				 }
			 }
			return found;
		} catch (Exception e){
			System.out.println("Error for CRL:" + e.getClass() + e.getMessage());
			return false;
		}
		
	}
	
	public void addToCRL(String tag, CVCertificate cert, Date dateRevoke, int allowance ) throws Exception, NoSuchFieldException{
		FileWriter fileWriter = null;
		byte[] signature = cert.getSignature();
		String hash = bytesToHex(signature);
		
		StorageOld.CRLWriter(String.valueOf(tag), String.valueOf(hash), String.valueOf(dateRevoke), String.valueOf(allowance));
	}
	
	
	public void removeFromCRL(){
		
	}


	// 1024 bits is not sufficient, but enough for testing phase
	public KeyPair RSAKeyGen() {
		try {
			System.out.println("Generating RSA keys, please wait...");
			final KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
			keyGen.initialize(RSA_BITS, new SecureRandom());
			final KeyPair keyPair = keyGen.generateKeyPair();		
			return keyPair;				
		} catch (Exception e) {
			System.out.println("Error in RSA key generation:" + e.getMessage());
			return null;
		}	
	}
	
	public static void writeKey(Key key, String filename) throws IOException {
		FileOutputStream file = new FileOutputStream(filename);
	//	file.write(key);
		file.close();
	}
	
	// Setting the monthly allowance that will be distributed to all charging terminals
	public short monthlyAllowance(){
		//Maybe perform a check if a terminal is a valid CT. 
		short allowance = 50; 	//Max. value is 32767 (inclusive).
		return allowance;
	}
	
	public static void main(final String args[]) throws Exception {
		CertificateCreator certificateCreator = new CertificateCreator();
		BouncyCastleProvider provider = new BouncyCastleProvider();
		Backend BE = new Backend();
		KeyPair keypair_backend = BE.RSAKeyGen();
		KeyPair keypair_terminal = BE.RSAKeyGen();
		
		CVCertificate cert_backend = certificateCreator.createCertificate(CertType.CA, keypair_backend, keypair_terminal);
		CVCertificate cert_terminal = certificateCreator.createCertificate(CertType.TERMINAL, keypair_backend, keypair_terminal);
		BE.addToCRL("T", cert_terminal , new Date(), 4);
		BE.addToCRL("C", cert_terminal , new Date(), 20);

		BE.isOnCRL(keypair_terminal,provider,cert_terminal,cert_backend);
		String certCA =  cert_backend.getAsText();
		System.out.println(certCA);
	}
}
