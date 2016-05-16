package backend;

import java.io.FileWriter;
import java.io.IOException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
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

@SuppressWarnings("unused")
enum CertType{
	CA, TERMINAL, CARD;
}

public class CertificateCreator implements GlobVarBE{
	final protected static char[] serialArray = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ".toCharArray();

	public CertificateCreator()throws Exception{
		
	}
	// TODO: no verification if a number has already been generated. Maybe if there is still time..
	protected String createRandomString(int length)
	{
		char[] serialChars = new char[length];
	    for(int i = 0; i<length; i++){
	        serialChars[i] = serialArray[new Random().nextInt(36)];
	    }
	    return new String(serialChars);
	}
			
	public CVCertificate createCertificate(CertType certType, KeyPair keypairCA, KeyPair keypairTerm) throws Exception {
		CAReferenceField caRef = new CAReferenceField("NL", "DUMMY", "00000");
		HolderReferenceField holderRef = new HolderReferenceField("NL", "DUMMY", "00000");
		String serialNrCA = "";
		String serialNrTerm = "";
		String serialNrCard = "";
		@SuppressWarnings("unused")
		String ID = "";
		String type = "";
		
		// TODO: figure out different roles and rights DV_F = Foreign, DV_D = Domestic, IS Extended Inspection System
		// See: www.commoncriteria.org/files/ppfiles/pp0056_V2b_pdf.pdf
		// DG3 = Fingerprint
		// DG4 = Irisscan
		AccessRights rights;
		AuthorizationRoleEnum role;
		PublicKey publicKey;
		PrivateKey privateKey;
		
		switch(certType){
		case CA:
			serialNrCA = createRandomString(5);
			caRef = new CAReferenceField("NL", "PetrolCA", serialNrCA);
			holderRef = new HolderReferenceField("NL", "PetrolCA", serialNrCA);
			rights = AccessRightEnum.READ_ACCESS_DG3_AND_DG4;
			role = AuthorizationRoleEnum.CVCA;
			type = "Type: CA Certificate";
			// private key CA for signing certificate
			privateKey = keypairCA.getPrivate();
			// public key Terminal for in certificate
			publicKey = keypairCA.getPublic();
			//return caRef, holderRef;
			break;
		case TERMINAL:
			serialNrTerm = createRandomString(5);
			caRef = new CAReferenceField("NL", "PetrolCA", serialNrTerm);
			holderRef = new HolderReferenceField("NL", "PCATerm", serialNrTerm);  //PCA = Petrol CA
			rights = AccessRightEnum.READ_ACCESS_DG3;
			role = AuthorizationRoleEnum.DV_D;
			type = "Type: Terminal Certificate";
			privateKey = keypairCA.getPrivate();
			// public key Terminal for in certificate
			publicKey = keypairTerm.getPublic();
			ID = createRandomString(9);
			break;
		case CARD: 
		default: 		// In case the role or rights have not been specified, this will be default setting. 
			serialNrCard = createRandomString(5);
			caRef = new CAReferenceField("NL", "PetrolCA", serialNrCard);
			holderRef = new HolderReferenceField("NL", "PCACard", serialNrCard);
			rights = AccessRightEnum.READ_ACCESS_NONE;
			role = AuthorizationRoleEnum.DV_F;
			type = "Type: Card Certificate";
			privateKey = keypairCA.getPrivate();
			// public key Terminal for in certificate
			publicKey = keypairTerm.getPublic();
			ID = createRandomString(9);
			break;
		}

		Calendar cal = Calendar.getInstance();

		String algorithmName = "SHA1WITHRSA";
		BouncyCastleProvider provider = new BouncyCastleProvider();
		Security.addProvider(provider);

		Date validFrom = new Date();
		cal.set(Calendar.YEAR, cal.get(Calendar.YEAR)+1); //Certificates will blow up on Feb 29th. :)
		Date validTo = cal.getTime();
		//DateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
		
		CVCertificate cert = CertificateGenerator.createCertificate(
				publicKey, privateKey, algorithmName, caRef, holderRef, role, rights,
				validFrom, validTo, provider.getName());
		String body = cert.getAsText();
		
		Storage storage = new Storage(type, String.valueOf(body));
		storage.CACertWriter();
			
		return cert;
	}
}
