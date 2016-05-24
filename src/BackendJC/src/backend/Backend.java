package backend;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.security.KeyPair;

// bouncycastle security provider 
import org.bouncycastle.jce.provider.BouncyCastleProvider;

// ejbca CVC imports
import org.ejbca.cvc.CVCertificate;
import org.ejbca.cvc.CertificateParser;

public class Backend implements GlobVarBE {

	public Backend() {
		
	}
	
	public static void main(final String args[]) throws Exception {
		CertCreate CCreate = new CertCreate();
		File CAPubKey = new File(CA_pubkey);
		File CAPrivKey = new File(CA_privkey);
		File CACertFile = new File(CA_CERT);
		BufferedReader scanInput = new BufferedReader(new InputStreamReader(System.in));
		final KeyPair keypair_backend;
		KeyPair keypair_misc;
		CertType type = null;
		String priv_key, pub_key, misc_cert;
		
		if (! (CAPubKey.exists() && CAPrivKey.exists() && CACertFile.exists())) {
			keypair_backend = CCreate.RSAKeyGen();
			final CVCertificate cert_backend = CCreate.CreateCACert(keypair_backend);
			String certData_CA = cert_backend.getAsText("", true);
			System.out.println("Certificate Data.....");
			System.out.println(certData_CA);
			System.out.println("Writing keypair to files.....");
			Storage.WriteCAKeyPair(keypair_backend);
			System.out.println("Writing CA Certificate to files.....");
			Storage.WriteCAFile(CACertFile, cert_backend.getDEREncoded());
		}
		else {
			System.out.println("Loading CA Certificate File.....");
			byte[] certData = Storage.LoadCAFile(CACertFile);
			CVCertificate cert_backend = CertificateParser.parseCertificate(certData);
			keypair_backend = Storage.LoadCAKeyPair();
			System.out.println("Checking if loaded CA Certificate is signed by the CA KeyPair (PublicKey)......");
			cert_backend.verify(keypair_backend.getPublic(), new BouncyCastleProvider().getName());
		}
		while (true) {
				System.out.println("What certificate would you like to create?");
				System.out.println("1) Terminal, 2) Card, 3) Quit");
				System.out.print("-->");
				int cert_type = Integer.parseInt(scanInput.readLine());
				if(cert_type == 1) {
					type = CertType.TERMINAL;

				} else if (cert_type == 2) {
					type = CertType.CARD;
				} else if (cert_type == 3) {
					System.out.println("Exiting and program shutting down now.....");
					System.out.flush();
					System.exit(0);
				}
				System.out.println("Where would you like to store the keypair for the terminal?");
				System.out.println("Type in the full path!");
				System.out.print("-->");
				String path = scanInput.readLine();
				String filename = CCreate.createRandomString(10);
				if(path.endsWith("/")) {
					priv_key = String.format("%s%s_priv.key", path, filename);
					pub_key = String.format("%s%s_pub.key", path, filename);
					misc_cert = String.format("%s%s.crt", path, filename);
				} else {
					priv_key = String.format("%s/%s_priv.key", path, filename);
					pub_key = String.format("%s/%s_pub.key", path, filename);
					misc_cert = String.format("%s/%s.crt", path, filename);
				}
				System.out.println("Your keypairs are stored in: ");
				System.out.printf("Private Key: %s", priv_key);
				System.out.println();
				System.out.printf("Public Key: %s", pub_key);
				System.out.println();
				keypair_misc = CCreate.RSAKeyGen();
				System.out.println("Writing the keypair to files.....");
				Storage.WriteKeyPair(new File(priv_key), new File(pub_key), keypair_misc);
				System.out.println("Creating your certificate for the terminal.....");
				CVCertificate cert_misc = CCreate.CreateMiscCert(type, keypair_backend.getPrivate(), keypair_misc.getPublic());
				System.out.println("The certificate is stored in: ");
				System.out.printf("Certificate: %s", misc_cert);
				System.out.println();
				System.out.println("Writing certificate data.....");
				Storage.WriteCAFile(new File(misc_cert), cert_misc.getDEREncoded());
				System.out.flush();
		}
	}
}
