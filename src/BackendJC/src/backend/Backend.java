package backend;

import java.io.*;
import java.security.*;
import java.security.interfaces.*;
import java.util.Calendar;
import java.util.Date;
import java.util.LinkedList;
import java.math.BigInteger;
import java.security.spec.*;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import org.jmrtd.cert.*;
import org.bouncycastle.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class Backend implements PublicKey, PrivateKey{
	
	// Deze klasse aanroepen van de functies om wat mee te doen

	public Backend(){
		KeyPair keypair = RSAKeyGen();
		createCertificate(keypair);
	}
	

	// Setting the monthly allowance that will be distributed to all chargingterminals
	public short monthlyAllowance(){
		//Maybe perform a check if a terminal is a valid CT. 
		short allowance = 50; 	//Max. value is 32767 (inclusive).
		return allowance;
	}
	
	// Return list of revoked  or CSV file
	public LinkedList<Integer> revokedLists(){
		LinkedList<Integer> list = new LinkedList<Integer>();
		return list;
	}
	
	// Import the Bouncy castle package to fix CVC Provider Error
	public CardVerifiableCertificate createCertificate(KeyPair keypair) {
	//	CVCertificateBuilder caBuilder;
		Calendar cal = Calendar.getInstance();
		PublicKey publicKey = keypair.getPublic();
		PrivateKey privateKey = keypair.getPrivate();
		CVCPrincipal caRef = new CVCPrincipal("NLTest00001");
		String algorithmName = "RSA";
		CVCPrincipal holderRef = new CVCPrincipal("NLWhoareyou00002");
		CVCAuthorizationTemplate authZTemplate = new CVCAuthorizationTemplate(CVCAuthorizationTemplate.Role.CVCA, CVCAuthorizationTemplate.Permission.READ_ACCESS_DG4);
//		String provider = "CVC";
//		String provider  = new BouncyCastleProvider();
		
		BouncyCastleProvider provider = new BouncyCastleProvider();
		Security.addProvider(provider);
		provider.setParameter(algorithmName, getAlgorithm());
	//	provider.getName();
		//String providerStr = Integer.toString(provider);

		
		
		
		//Security.addProvider(new BouncyCastleProvider("AES"));
		//String providerStr = Integer.toString(provider);
//		provider.getName(provider);
		
		
		Date validFrom = new Date();
		cal.set(Calendar.YEAR, cal.get(Calendar.YEAR)+1);
		Date validTo = cal.getTime();
		DateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
		System.out.println(dateFormat.format(cal.getTime()));
//		caBuilder = new CVCertificateBuilder();
		try {
//			CardVerifiableCertificate cert = CVCertificateBuilder.createCertificate(publicKey, privateKey, algorithmName, caRef, holderRef, authZTemplate, validFrom, validTo, provider);
			CardVerifiableCertificate cert = CVCertificateBuilder.createCertificate(publicKey, privateKey, algorithmName, caRef, holderRef, authZTemplate, validFrom, validTo, provider.getName());
			return cert;
		} catch (Exception e){
			System.out.println("Error:" + e.getMessage());
		}
		return null;
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
	public KeyPair RSAKeyGen(){
		try {
			System.out.println("Generating RSA keys, please wait...");
			KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
			generator.initialize(1984);		
			KeyPair keypair = generator.generateKeyPair();
		
			return keypair;		
		
		} catch (Exception e){
			System.out.println("Error:" + e.getMessage());
			return null;
		}	
	}
	
	public static void writeKey(Key key, String filename) throws IOException {
		FileOutputStream file = new FileOutputStream(filename);
		file.write(key.getEncoded());
		file.close();
	}
}