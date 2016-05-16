package backend;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.Arrays;

import au.com.bytecode.opencsv.CSVWriter;

@SuppressWarnings("unused")
public class Storage implements GlobVarBE {

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
	public Storage(String Type, String Body) throws Exception {
		this.FileName = CA_CERT;
		this.Type = Type;
		this.Body = Body;
	}
	
	/* constructor for CRL list writing */
	public Storage(String Tag, String Hash, String DataRevoke, String Allowance) throws Exception {
		this.FileName = CRL_FILE;
		this.Tag = Tag;
		this.Hash = Hash;
		this.DataRevoke = DataRevoke;
		this.Allowance = Allowance;
	}

	/* Specific writer method for CACert storage */
	public void CACertWriter() throws IOException {
		FileWriter filewriter = null;
		
		try{
			filewriter = new FileWriter(this.FileName, true);
			filewriter.write(this.CACertmakeString());
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
	public void CRLWriter() throws IOException {
		CSVWriter csvwriter = null;
		File file = new File(this.FileName);
		try {
			if (file.exists()) {
				csvwriter = new CSVWriter(new FileWriter(file, true), CSVWriter.DEFAULT_SEPARATOR, CSVWriter.NO_QUOTE_CHARACTER);
				csvwriter.writeNext(this.CRLmakeString());
			} else {
				csvwriter = new CSVWriter(new FileWriter(file, true), CSVWriter.DEFAULT_SEPARATOR, CSVWriter.NO_QUOTE_CHARACTER);
				csvwriter.writeNext(CRL_HEADER);
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
	
	private String CACertmakeString() {
		String result = new String();
		result += CAHeader;
		result += NEW_LINE_SEPERATOR;
		result += this.Type;
		result += NEW_LINE_SEPERATOR;
		result += this.Body;
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
