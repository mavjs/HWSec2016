package backend;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Calendar;
import java.util.Date;
import java.util.Random;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.ejbca.cvc.AccessRightEnum;
import org.ejbca.cvc.AccessRights;
import org.ejbca.cvc.AuthorizationRoleEnum;
import org.ejbca.cvc.CAReferenceField;
import org.ejbca.cvc.CVCertificate;
import org.ejbca.cvc.CertificateGenerator;
import org.ejbca.cvc.HolderReferenceField;

/**
 * 
 * Main helper class to create Certificates
 * 
 * @author Group 2, Hardware Security 2016
 * @version $Id: CertCreate.java 0.1 2016-05-21 $
 *
 */
public class CertCreate implements GlobVarBE {
	final protected static char[] serialArray = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ".toCharArray();
	final protected BouncyCastleProvider provider = new BouncyCastleProvider();
	
	/* Constructor for CertCreate */
	public CertCreate() {
		Security.addProvider(this.provider);
	}
	
	// TODO: no verification if a number has already been generated.
	/**
	 * Protected method returning a random string
	 * @param length
	 * @return
	 */
	protected String createRandomString(int length)
	{
		char[] serialChars = new char[length];
	    for(int i = 0; i<length; i++){
	        serialChars[i] = serialArray[new Random().nextInt(36)];
	    }
	    return new String(serialChars);
	}
	
	// 1024 bits is not sufficient, but enough for testing phase
	/**
	 * KeyPair Generator for CertCreate
	 * @return
	 */
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
	
	/**
	 * Method to create Certificate
	 * @param certType, keyPairCA, keyPairTerm
	 * @throws Exception
	 * @return
	 */
	public CVCertificate CreateCACert(KeyPair keypairCA) throws Exception {
		CAReferenceField caRef = null;
		HolderReferenceField holderRef = null;
		String serialNrCA;
		AccessRights rights = null;
		AuthorizationRoleEnum role = null;
		PublicKey publicKey = null;
		PrivateKey privateKey = null;
	
		serialNrCA = createRandomString(5);
		caRef = new CAReferenceField("NL", "PetrolCA", serialNrCA);
		holderRef = new HolderReferenceField("NL", "PetrolCA", serialNrCA);
		rights = AccessRightEnum.READ_ACCESS_DG3_AND_DG4;
		role = AuthorizationRoleEnum.CVCA;
		// typeCert = "Type: CA Certificate";
		// private key CA for signing certificate
		privateKey = keypairCA.getPrivate();
		// public key Terminal for certificate
		publicKey = keypairCA.getPublic();

		Date validFrom = new Date();
		Date validTo = this.ValidToDate();
		
		CVCertificate cert = CertificateGenerator.createCertificate(
				publicKey, privateKey, ALGORITHMNAME, caRef, holderRef, role, rights,
				validFrom, validTo, this.provider.getName());
			
		return cert;
	}
		
	public CVCertificate CreateMiscCert(CertType certType, PrivateKey PrivateKeyCA, PublicKey PublicKeyMisc) throws Exception {
		CAReferenceField caRef = null;
		HolderReferenceField holderRef = null;
		AccessRights rights = null;
		AuthorizationRoleEnum role = null;
		PublicKey publicKey = null;
		PrivateKey privateKey = null;
		String serialNrTerm, serialNrCard;
		
		switch(certType) {
		case TERMINAL: 
		default:
			serialNrTerm = createRandomString(5);
			caRef = new CAReferenceField("NL", "PetrolCA", serialNrTerm);
			holderRef = new HolderReferenceField("NL", "PCATerm", serialNrTerm);  //PCA = Petrol CA
			rights = AccessRightEnum.READ_ACCESS_DG3;
			role = AuthorizationRoleEnum.DV_D;
			//typeCert = "Type: Terminal Certificate";
			privateKey = PrivateKeyCA;
			// public key Terminal for in certificate
			publicKey = PublicKeyMisc;
			break;
		case CARD: 		
			// In case the role or rights have not been specified, this will be default setting. 
			serialNrCard = createRandomString(5);
			caRef = new CAReferenceField("NL", "PetrolCA", serialNrCard);
			holderRef = new HolderReferenceField("NL", "PCACard", serialNrCard);
			rights = AccessRightEnum.READ_ACCESS_NONE;
			role = AuthorizationRoleEnum.DV_F;
			//typeCert = "Type: Terminal Certificate";
			privateKey = PrivateKeyCA;
			// public key Terminal for in certificate
			publicKey = PublicKeyMisc;
			break;
		}

		Date validFrom = new Date();
		Date validTo = this.ValidToDate();
		
		CVCertificate cert = CertificateGenerator.createCertificate(
				publicKey, privateKey, ALGORITHMNAME, caRef, holderRef, role, rights,
				validFrom, validTo, this.provider.getName());
			
		return cert;
	}
	
	private Date ValidToDate() {
		Calendar cal = Calendar.getInstance();
		// Certificates will blow up on Feb 29th.
		cal.set(Calendar.YEAR, cal.get(Calendar.YEAR)+1);
		Date validTo = cal.getTime();
		return validTo;
	}
}
