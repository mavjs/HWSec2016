package backend;

import java.io.File;
import java.security.KeyPair;

// bouncycastle security provider 
import org.bouncycastle.jce.provider.BouncyCastleProvider;

// ejbca CVC imports
import org.ejbca.cvc.CVCertificate;
import org.ejbca.cvc.CertificateParser;

public class CertCreateTest implements GlobVarBE {

	public CertCreateTest() {
		
	}
	
	public static void main(final String args[]) throws Exception {
		CertCreate CCreate = new CertCreate();
		File CAPubKey = new File(CA_pubkey);
		File CAPrivKey = new File(CA_privkey);
		File CACertFile = new File(CA_CERT);
		
		if (! (CAPubKey.exists() && CAPrivKey.exists() && CACertFile.exists())) {
			final KeyPair keypair_backend = CCreate.RSAKeyGen();
			final CVCertificate cert_backend = CCreate.CreateCACert(keypair_backend);
			String certData_CA = cert_backend.getAsText("", true);
			System.out.println("Certificate Data.....");
			System.out.println(certData_CA);
			System.out.println("Writing keypair to files.....");
			Storage.WriteKeyPair(keypair_backend);
			System.out.println("Writing CA Certificate to files.....");
			Storage.WriteCAFile(CACertFile, cert_backend.getDEREncoded());
		}
		else {
			System.out.println("Loading CA Certificate File.....");
			byte[] certData = Storage.LoadCAFile(CACertFile);
			CVCertificate cert_backend = CertificateParser.parseCertificate(certData);
			System.out.println("Loading CA KeyPair File.....");
			KeyPair test_keypair_backend = Storage.LoadKeyPair();
			System.out.println("Checking if loaded CA Certificate is signed by the CA KeyPair (PublicKey)......");
			cert_backend.verify(test_keypair_backend.getPublic(), new BouncyCastleProvider().getName());
		}
	}
}
