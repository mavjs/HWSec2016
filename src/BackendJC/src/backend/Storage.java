package backend;

import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import au.com.bytecode.opencsv.CSVWriter;

public class Storage implements GlobVarBE {

	public Storage() {
	}
	
	public static void WriteKeyPair(KeyPair keypair) throws IOException {
		FileOutputStream fos = null;
		PrivateKey privatekey = keypair.getPrivate();
		PublicKey publickey = keypair.getPublic();
			
		// Store Public Key
		X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(publickey.getEncoded());
		try {
			fos = new FileOutputStream(CA_pubkey);
			fos.write(x509EncodedKeySpec.getEncoded());
		} finally {
			fos.close();
		}
			
		// Store Private Key.
		PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(privatekey.getEncoded());
		try {
			fos = new FileOutputStream(CA_privkey);
			fos.write(pkcs8EncodedKeySpec.getEncoded());
		} finally {
			fos.close();
		}
	}
	
	public static KeyPair LoadKeyPair() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
		FileInputStream fis = null;
		byte[] encodedPublicKey, encodedPrivateKey;

		try {
			// Read Public Key.
			File filePublicKey = new File(CA_pubkey);
			fis = new FileInputStream(CA_pubkey);
			encodedPublicKey = new byte[(int) filePublicKey.length()];
			fis.read(encodedPublicKey);
		} finally {
			if(fis != null) {
				fis.close();
			}
		}
	 
		try {
			// Read Private Key.
			File filePrivateKey = new File(CA_privkey);
			fis = new FileInputStream(CA_privkey);
			encodedPrivateKey = new byte[(int) filePrivateKey.length()];
			fis.read(encodedPrivateKey);
		} finally {
			fis.close();
		}
	 
		// Generate KeyPair.
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(encodedPublicKey);
		PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
	 
		PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(encodedPrivateKey);
		PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);
	 
		return new KeyPair(publicKey, privateKey);
	}
	
	public static void WriteCAFile(final File certfile, final byte[] cert) throws IOException {
		FileOutputStream fos = null;
		BufferedOutputStream bos = null;
		try {
			fos = new FileOutputStream(certfile);
			bos = new BufferedOutputStream(fos, 1024);
			bos.write(cert);
		} finally {
			if(bos != null) {
				bos.close();
			}
		}
	}
	
	public static byte[] LoadCAFile(final File certfile) throws IOException {
	     byte[] dataBuffer = null;
	      FileInputStream inStream = null;
	      try {
	         // Simple file loader...
	         final int length = (int)certfile.length();
	         dataBuffer = new byte[length];
	         inStream = new FileInputStream(certfile);
	         inStream.read(dataBuffer);
	      }
	      finally {
	    	  if (inStream != null) {
	    		  inStream.close();
	          }
	      }
	      return dataBuffer;
	}
	
	/* Specific writer method for CRL list storage */
	public static void CRLWriter(String Tag, String Hash, String DataRevoke, String Allowance) throws IOException {
		CSVWriter csvwriter = null;
		File file = new File(CRL_FILE);
		try {
			if (file.exists()) {
				csvwriter = new CSVWriter(new FileWriter(file, true), CSVWriter.DEFAULT_SEPARATOR, CSVWriter.NO_QUOTE_CHARACTER);
				csvwriter.writeNext(new String[]{Tag, Hash, DataRevoke, Allowance});
			} else {
				csvwriter = new CSVWriter(new FileWriter(file, true), CSVWriter.DEFAULT_SEPARATOR, CSVWriter.NO_QUOTE_CHARACTER);
				csvwriter.writeNext(CRL_HEADER);
				csvwriter.writeNext(new String[]{Tag, Hash, DataRevoke, Allowance});
			}
		} catch (IOException ioe) {
			System.out.println("IOException: " + ioe.getMessage());
		} finally {
			if (csvwriter != null) {
				System.out.println("Storing CRL data was successful!");
				csvwriter.close();
			}
			else {
				System.out.println("Storing CRL data was unsuccessful!");
			}
		}
	}
}
