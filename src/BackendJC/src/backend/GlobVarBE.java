package backend;

public interface GlobVarBE {
	public static final Integer RSA_BITS = 1024;
	
	//Delimiters and file headers used in CSV file for CRL
	public static final String COMMA_DELIMITER = ",";
	public static final String NEW_LINE_SEPERATOR = "\n";
	public static final String CRL_FILE = "crl.csv";
	public static final String[] CRL_HEADER = {"tag", "ID", "dateRevocation", "allowance"};
	
	public static final String CA_CERT = "ca-cert.crt";
	public static final String CAHeader = "--------BEGIN-CERTIFICATE--------";
	public static final String CAFooter = "--------END-CERTIFICATE--------";
	public static final String CA_privkey = "ca_priv.key";
	public static final String CA_pubkey = "ca_pub.key";
	public static enum CertType{
		CA, TERMINAL, CARD;
	}
	
	public static final String ALGORITHMNAME = "SHA1WITHRSA";
	
}
