package backend;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;

import au.com.bytecode.opencsv.CSVWriter;

@SuppressWarnings("unused")
public class StorageOld implements GlobVarBE {

	/* Generic variables */
	public String FileName;
	
	/* CACert specific variables */
	public String Type;
	public String Body;

	/* CRL specific variables */
	public String Tag;
	public String Hash;
	public String DataRevoke;
	public String Allowance;
	
	/* constructor for CACert writing */
	public StorageOld(String Type, String Body) throws Exception {
		this.FileName = CA_CERT;
		this.Type = Type;
		this.Body = Body;
	}
	
	/* constructor for CRL list writing */
	public StorageOld(String Tag, String Hash, String DataRevoke, String Allowance) throws Exception {
		this.FileName = CRL_FILE;
		this.Tag = Tag;
		this.Hash = Hash;
		this.DataRevoke = DataRevoke;
		this.Allowance = Allowance;
	}

	/* Specific writer method for CACert storage */
	public static void CACertWriter(String Type, String Body) throws IOException {
		FileWriter filewriter = null;
		
		try{
			filewriter = new FileWriter(CA_CERT, true);
			filewriter.write(CACertmakeString(Type, Body));
		} catch (IOException ioe) {
			System.out.println("IOException: " + ioe.getMessage());
		} finally {
			if (filewriter != null) {
				System.out.println("Storing CACert data was successful!");
				filewriter.close();
			}
			else {
				System.out.println("Storing CACert data was unsuccessful!");
			}
		}
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
				System.out.println("Storing CRL data was successful!");
			}
		}
	}
	
	private static String CACertmakeString(String Type, String Body) {
		String result = new String();
		result += CAHeader;
		result += NEW_LINE_SEPERATOR;
		result += Type;
		result += NEW_LINE_SEPERATOR;
		result += Body;
		result += NEW_LINE_SEPERATOR;
		result += CAFooter;
		result += NEW_LINE_SEPERATOR;
		
		return result;
	}
	
	private String[] CRLmakeString() {
		String[] result = {this.Tag, this.Hash, this.DataRevoke, this.Allowance};

		return result;
	}
}
