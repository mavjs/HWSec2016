package backend;

import java.io.*;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.interfaces.*;
import java.util.Calendar;
import java.util.Date;
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

public class Backend implements PublicKey, PrivateKey{
	//Delimiters used in CSV file for CRL
	private static final String COMMA_DELIMITER = ",";
	private static final String NEW_LINE_SEPERATOR = "\n";
	private static final Integer RSA_BITS = 1984;
	private static final String CRL_FILE = "crl.csv";
	
	//CSV file header
	private static final String FILE_HEADER = "tag,ID,dateRevocation,allowance";
	
	// Deze klasse aanroepen van de functies om wat mee te doen

	public Backend(){
//		KeyPair keypair_backend = RSAKeyGen();
		KeyPair keypair_terminal = RSAKeyGen();
//		CardVerifiableCertificate cert_backend = createCertificate(keypair_backend);
		CardVerifiableCertificate cert_terminal = createCertificate(keypair_terminal);
		addToCRL("T", cert_terminal , new Date(), 4);
		isOnCRL(cert_terminal);
	}
	

	// Setting the monthly allowance that will be distributed to all chargingterminals
	public short monthlyAllowance(){
		//Maybe perform a check if a terminal is a valid CT. 
		short allowance = 50; 	//Max. value is 32767 (inclusive).
		return allowance;
	}
	
	/* For every transaction this method is called. 
	 * Verification will be done if the card and terminal are on the CRL
	 * 		IF YES: transaction should be stopped and entry should be logged?
	 * 		IF NOT: continue transaction
	 */
	
	public static boolean verifyValidityTransactionCertificates(String tag, int id, Date dateRevoke, int allowance, CardVerifiableCertificate cert){
		try {
			byte[] signature = cert.getSignature();

			cert.getAuthorityReference();
			return false;
		} catch (Exception e){
			System.out.println("Error in validity checking:" + e.getMessage());
			return false;
		}
		
		
		
		// verify if card is on CRL list
		//verify if Cert is signed by private key.
		// verify if date of certificate is still valid

	}
	/* CRL consists of: 
	Tag (C or T), C = Card T = Terminal
	id = ID number of card or terminal
	date-time of revocation, so current date
	allowance before revocation 
	*/
	
	/* Requires that a certificate is signed
	 * 
	 * */
	
	public static boolean isOnCRL(CardVerifiableCertificate cert){
		BufferedReader buffer = null;
		StringBuilder sb = new StringBuilder();
				
		try {
			String line;
			 buffer = new BufferedReader(new FileReader(CRL_FILE));
			byte[] signature = cert.getSignature();
			byte[] certbody = cert.getCertBodyData();
			byte[] certenc = cert.getEncoded();
			int hash = cert.hashCode();
			
			// NEXT STEP IS TO SIGN THE CERTIFICATES CREATED BEFORE I CAN CONTINUE
			
			
//			System.out.printf("Signature: %s \n Cert body: %s\n Cert enc %s\n Hash %s\n ", signature, certbody, certenc, hash);
		//	System.out.printf("Cert body: ", certbody);
			//System.out.printf("Signature2: ", signature);
			 while((line = buffer.readLine()) != null) {
				 System.out.println("line starts here: \n");
				 System.out.println( line);
				//Do magic for checking if signature is somewhere on CRL
//				String[] tokens = line.split(COMMA_DELIMITER);
			 	//if (tokens.length > 0){
				 continue;
			 }
			 			
			System.out.println("Sweet, CSV succesfull.\n");
			return true;
		} catch (Exception e){
			System.out.println("Error in adding to CRL:" + e.getMessage());
		} finally {
			try {
	//			fileReader.close();
				return false;
			} catch (Exception e) {
				// TODO Auto-generated catch block
				System.out.println("Error in adding to CRL: " + e.getMessage());
				return false;
			}		
		}
		
	}
	
	public static void addToCRL(String tag, CardVerifiableCertificate cert, Date dateRevoke, int allowance ){
		FileWriter fileWriter = null;
				
		try {
			fileWriter = new FileWriter(CRL_FILE);
			
			fileWriter.append(FILE_HEADER.toString());
			fileWriter.append(NEW_LINE_SEPERATOR.toString());
			
			fileWriter.append(String.valueOf(tag));
			fileWriter.append(COMMA_DELIMITER);
			fileWriter.append(String.valueOf(cert.getSignature()));
			fileWriter.append(COMMA_DELIMITER);
			fileWriter.append(String.valueOf(dateRevoke));
			fileWriter.append(COMMA_DELIMITER);
			fileWriter.append(String.valueOf(allowance));
			fileWriter.append(NEW_LINE_SEPERATOR);
			
			System.out.println("Sweet, CSV succesfull");
			
		} catch (Exception e){
			System.out.println("Error in adding to CRL:" + e.getMessage());
		} finally {
			try {
				fileWriter.flush();
				fileWriter.close();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				System.out.println("Error in adding to CRL: " + e.getMessage());
			}		
		}
	}
	
	
	public void removeFromCRL(){
		
	}
	
	public CardVerifiableCertificate createCertificate(KeyPair keypair) {
		Calendar cal = Calendar.getInstance();
		PublicKey publicKey = keypair.getPublic();
		PrivateKey privateKey = keypair.getPrivate();
		CVCPrincipal caRef = new CVCPrincipal("NLTest00001");
		String algorithmName = "SHA1withRSA";
		CVCPrincipal holderRef = new CVCPrincipal("NLWhoareyou00002");
		CVCAuthorizationTemplate authZTemplate = new CVCAuthorizationTemplate(CVCAuthorizationTemplate.Role.CVCA, CVCAuthorizationTemplate.Permission.READ_ACCESS_DG4);
		
		BouncyCastleProvider provider = new BouncyCastleProvider();
		Security.addProvider(provider);

		Date validFrom = new Date();
		cal.set(Calendar.YEAR, cal.get(Calendar.YEAR)+1); //Certificates will blow up on Feb 29th. :)
		Date validTo = cal.getTime();
		DateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
//		System.out.println(dateFormat.format(cal.getTime()));
		
		try {
			CardVerifiableCertificate cert = CVCertificateBuilder.createCertificate(publicKey, privateKey, algorithmName, caRef, holderRef, authZTemplate, validFrom, validTo, provider.getName());
			keypair.
			return cert;
		} catch (Exception e){
			System.out.println("Error in certificate creation: " + e.getMessage());
			return null;
		}
	} 


	@Override
	public String getAlgorithm() {
		// TODO Auto-generated method stub
		return null;
	}


	@Override
	public byte[] getEncoded() {
		// TODO Auto-generated method stub
		return null;
	}


	@Override
	public String getFormat() {
		// TODO Auto-generated method stub
		return null;
	}

	// 1024 bits is not sufficient, but enough for testing phase
	public KeyPair RSAKeyGen() {
		try {
			System.out.println("Generating RSA keys, please wait...");
			KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
			generator.initialize(RSA_BITS);		
			KeyPair keypair = generator.generateKeyPair();
		
			return keypair;				
		} catch (Exception e) {
			System.out.println("Error in RSA key generation:" + e.getMessage());
			return null;
		}	
	}
	
	public static void writeKey(Key key, String filename) throws IOException {
		FileOutputStream file = new FileOutputStream(filename);
		file.write(key.getEncoded());
		file.close();
	}
}
