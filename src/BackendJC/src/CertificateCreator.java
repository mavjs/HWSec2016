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

enum CertType{
	CA, TERMINAL, CARD;
}

public class CertificateCreator implements GlobVarBE{
	public CertificateCreator()throws Exception{
		
	}

	protected String createRandomSerial(String serial)
	{
	    // syntax we would like to generate is DIA123456-A1B34      
	    String val = "";      

/*	    // char (1), random A-Z
	    int ranChar = 65 + (new Random()).nextInt(90-65);
	    char ch = (char)ranChar;        
	    val += ch;      

	    // numbers (5), random 0-9
	    Random r = new Random();
	    int numbers = 100000 + (int)(r.nextFloat() * 899900);
	    val += String.valueOf(numbers);

	    val += "-";
*/
	    // char or numbers (5), random 0-9 A-Z
	    for(int i = 0; i<5;){
	        int ranAny = 48 + (new Random()).nextInt(90-65);

	        if(!(57 < ranAny && ranAny<= 65)){
	        char c = (char)ranAny;      
	        val += c;
	        i++;
	        }
	    }
	    return val;
	}
	protected String createID(String serial)
	{
	    // syntax we would like to generate is DIA123456-A1B34      
	    String val = "";      

/*	    // char (1), random A-Z
	    int ranChar = 65 + (new Random()).nextInt(90-65);
	    char ch = (char)ranChar;        
	    val += ch;      

	    // numbers (5), random 0-9
	    Random r = new Random();
	    int numbers = 100000 + (int)(r.nextFloat() * 899900);
	    val += String.valueOf(numbers);

	    val += "-";
*/
	    // char or numbers (5), random 0-9 A-Z
	    for(int i = 0; i<5;){
	        int ranAny = 48 + (new Random()).nextInt(90-65);

	        if(!(57 < ranAny && ranAny<= 65)){
	        char c = (char)ranAny;      
	        val += c;
	        i++;
	        }
	    }
	    return val;
	}
		
	public CVCertificate createCertificate(CertType certType, KeyPair keypairCA, KeyPair keypairTerm) throws Exception {
		System.out.println("I got here");

		CAReferenceField caRef = new CAReferenceField("NL", "DUMMY", "00000");
		HolderReferenceField holderRef = new HolderReferenceField("NL", "DUMMY", "00000");

		String serialNrCA = "";
		String serialNrTerm = "";
		String serialNrCard = "";
		String ID = "";
		
		System.out.println("I got here");
		switch(certType){
		case CA:
			serialNrCA = createRandomSerial(serialNrCA);
			caRef = new CAReferenceField("NL", "PetrolCA", serialNrCA);
			holderRef = new HolderReferenceField("NL", "PetrolCA", serialNrCA);
			//return caRef, holderRef;
			break;
		case TERMINAL:
			serialNrTerm = createRandomSerial(serialNrTerm);
			caRef = new CAReferenceField("NL", "PetrolCA", serialNrTerm);
			holderRef = new HolderReferenceField("NL", "TerminalCertificate", serialNrTerm);
			ID = createID(ID);
			break;
		case CARD: 
			serialNrCard = createRandomSerial(serialNrCard);
			caRef = new CAReferenceField("NL", "PetrolCA", serialNrCard);
			holderRef = new HolderReferenceField("NL", "CardCertificate", serialNrCard);
			ID = createID(ID);
			break;
		}
		
		FileWriter fileWriter = null;
		Calendar cal = Calendar.getInstance();
		// private key CA for signing certificate
		PrivateKey privateKeyCA = keypairCA.getPrivate();
		// public key Terminal for in certificate
		PublicKey publicKeyTerm = keypairTerm.getPublic();
		String algorithmName = "SHA1WITHRSA";
		System.out.println("Maybe here too");

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
}
