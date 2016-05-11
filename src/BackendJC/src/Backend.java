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

public class Backend implements PublicKey, PrivateKey, GlobVarBE{
	CertificateCreator certificateCreator; 
	BouncyCastleProvider provider;
	
	public Backend() throws Exception {
		certificateCreator = new CertificateCreator();
		KeyPair keypair_backend = RSAKeyGen();
		KeyPair keypair_terminal = RSAKeyGen();
		System.out.println(CertType.CA);
		System.out.println(keypair_backend);
		System.out.println(keypair_terminal);
		
		CVCertificate cert_backend = certificateCreator.createCertificate(CertType.CA, keypair_backend, keypair_terminal);
//		CVCertificate cert_terminal = createTerminalCertificate(keypair_backend, keypair_terminal);
//		addToCRL("T", cert_terminal , new Date(), 4);
//		isOnCRL(keypair_backend, provider, cert_terminal, cert_backend);
		String certCA =  cert_backend.getAsText();
//		System.out.print(certCA);
//		String certTerm = cert_terminal.getAsText();
//		System.out.print(certTerm);
	}	
	/* For every transaction this method is called. 
	 * Verification will be done if the card and terminal are on the CRL
	 * 		IF YES: transaction should be stopped and entry should be logged?
	 * 		IF NOT: continue transaction
	 */
	
		
	
	public static boolean verifyValidityTransactionCertificates(String tag, int id, Date dateRevoke, int allowance, CardVerifiableCertificate cert){
		try {
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
	/* CRL consists of: 
	Tag (C or T), C = Card T = Terminal
	id = ID number of card or terminal
	date-time of revocation, so current date
	allowance before revocation 
	*/
	
	/* Requires that a certificate is signed
	 * 
	 * */
	
	public static boolean isOnCRL(KeyPair key, BouncyCastleProvider provider, CVCertificate cert, CVCertificate cert_ca){
		BufferedReader buffer = null;
		StringBuilder sb = new StringBuilder();
				
		try {
			String line;
			buffer = new BufferedReader(new FileReader(CRL_FILE));
			byte[] signature = cert.getSignature();
	//		byte[] certbody = cert.getCertBodyData();
		//	byte[] certenc = cert.getEncoded();
			int hash = cert.hashCode();
			
			// NEXT STEP IS TO SIGN THE CERTIFICATES CREATED BEFORE I CAN CONTINUE
	//		cert.verify(key.getPublic());
			cert.verify(key.getPublic(), provider.getName());
			
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
			return false;
		}
/*		} finally {
			try {
				return false;
			} catch (Exception e) {
				// TODO Auto-generated catch block
				System.out.println("Error in adding to CRL: " + e.getMessage());
				return false;
			}		
		} */
		
	}
	
	public static void addToCRL(String tag, CVCertificate cert, Date dateRevoke, int allowance ){
		FileWriter fileWriter = null;
				
		try {
			fileWriter = new FileWriter(CRL_FILE,true);
			
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

	/* Keypair of CA is used to create a self-signed certificate for the backend. 
	 * For the terminals and smartcards use the other certificate creation function.
	 * 
	 * */
	/*
	public CVCertificate createCACertificate(KeyPair keypairCA) throws Exception {
		FileWriter fileWriter = null;
		Calendar cal = Calendar.getInstance();
		PublicKey publicKeyCA = keypairCA.getPublic();
		PrivateKey privateKeyCA = keypairCA.getPrivate();
		CAReferenceField caRef = new CAReferenceField("NL", "PetrolCA", "00001" );

		String algorithmName = "SHA1WITHRSA";
		HolderReferenceField holderRef = new HolderReferenceField("NL", "PetrolCA","00001");
		
		// TODO: figure out difference between rights and roles
		AuthorizationRoleEnum role = AuthorizationRoleEnum.CVCA;		
		AccessRights rights = AccessRightEnum.READ_ACCESS_DG3_AND_DG4;
		
		BouncyCastleProvider provider = new BouncyCastleProvider();
		Security.addProvider(provider);

		Date validFrom = new Date();
		cal.set(Calendar.YEAR, cal.get(Calendar.YEAR)+1); //Certificates will blow up on Feb 29th. :)
		Date validTo = cal.getTime();
		DateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
//		System.out.println(dateFormat.format(cal.getTime()));
		
		// Create the certificate and write it to a file, new certs can be recognised by BEGIN and END tags
		try {		
			CVCertificate cert = CertificateGenerator.createCertificate(
					publicKeyCA, privateKeyCA, algorithmName, caRef, holderRef, role, rights,
					validFrom, validTo, provider.getName());
			String body = cert.getAsText();
			fileWriter = new FileWriter(CA_CERT, true);
			fileWriter.append("-----BEGIN-CERTIFICATE----------------\n");
			fileWriter.append("PetrolCertificate: CA");
			fileWriter.append(NEW_LINE_SEPERATOR.toString());
			fileWriter.append(String.valueOf(body));
			fileWriter.append("\n-----END-CERTIFICATE------------------\n");
//			System.out.print(body);
			return cert;
		} catch (Exception e){
			System.out.println("Error in certificate creation: " + e.getMessage());
			return null;
		} finally {
			fileWriter.flush();
			fileWriter.close();
		}
	} 
	
	*/
	/* Terminal
	 * */
	// TODO: make function to serienumber uit te geven en functie om op te vragen wat de volgende is.
	// terminalID is bijv: CT of PT en dan het ID number ervan
	// Serialnumber is serienumber van certificate used for revocation
/*
	public CVCertificate createTerminalCertificate(KeyPair keypairCA, KeyPair keypairTerm, String terminalID) throws IOException {
		FileWriter fileWriter = null;
		Calendar cal = Calendar.getInstance();
		// private key CA for signing certificate
		PrivateKey privateKeyCA = keypairCA.getPrivate();
		// public key Terminal for in certificate
		PublicKey publicKeyTerm = keypairTerm.getPublic();
		CAReferenceField caRef = new CAReferenceField("NL", "PetrolCA", "00001" );
		String algorithmName = "SHA1WITHRSA";

		//TODO: change 00001 to serialnumber that will increase with every new cert generated
		HolderReferenceField holderRef = new HolderReferenceField("NL", "TerminalID", "00001");
		
		// TODO: figure out different roles and rights DV_F = Foreign, DV_D = Domestic
		AuthorizationRoleEnum role = AuthorizationRoleEnum.IS;
		AccessRights rights = AccessRightEnum.READ_ACCESS_DG3;
		
		BouncyCastleProvider provider = new BouncyCastleProvider();
		Security.addProvider(provider);

		Date validFrom = new Date();
		cal.set(Calendar.YEAR, cal.get(Calendar.YEAR)+1); //Certificates will blow up on Feb 29th. :)
		Date validTo = cal.getTime();
		DateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
//		System.out.println(dateFormat.format(cal.getTime()));
		
		try {		
			CVCertificate cert = CertificateGenerator.createCertificate(
					publicKeyTerm, privateKeyCA, algorithmName, caRef, holderRef, role, rights,
					validFrom, validTo, provider.getName());
			String body = cert.getAsText();
			fileWriter = new FileWriter(CA_CERT, true);
			fileWriter.append("-----BEGIN-CERTIFICATE----------------\n");
			fileWriter.append("PetrolCertificate: Client");
			fileWriter.append(NEW_LINE_SEPERATOR.toString());
			fileWriter.append(String.valueOf(body));
			fileWriter.append("\n-----END-CERTIFICATE------------------\n");
			return cert;
		} catch (Exception e){
			System.out.println("Error in certificate creation: " + e.getMessage());
			return null;
		} finally {
			fileWriter.flush();
			fileWriter.close();
		}
	} 
*/
	@Override
	public String getAlgorithm() {
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
			final KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
			keyGen.initialize(RSA_BITS, new SecureRandom());
			final KeyPair keyPair = keyGen.generateKeyPair();
	//		KeyPair keypair = keyGen.generateKeyPair();
		
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
	
	// Setting the monthly allowance that will be distributed to all chargingterminals
	public short monthlyAllowance(){
		//Maybe perform a check if a terminal is a valid CT. 
		short allowance = 50; 	//Max. value is 32767 (inclusive).
		return allowance;
	}

	@Override
	public byte[] getEncoded() {
		// TODO Auto-generated method stub
		return null;
	}
}
