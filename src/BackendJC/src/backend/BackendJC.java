package backend;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.LinkedList;

// Deze klasse gebruiken om unittests mee uit te voeren, controleren of de code werkt

public class BackendJC {
	Backend be;
	
	BackendJC() {
		be = new Backend();
		if (!testrevokedLists()) {
			System.out.println("OMG Noes! revokedLists failed.");
		}
		if (!testSomeOtherMethod()) {
			System.out.println("OMG noes! SomeOtherMethod failed.");
		}
		short allowance = getAllowance();
		System.out.println("Monthly allowance is: " + allowance);
	//	testKeyCreation();
	}
	
	short getAllowance(){
		short allowance = be.monthlyAllowance();
		return allowance;
	}
	
	public static void main(String[] arg){
		new BackendJC();
	}
	
    Boolean testrevokedLists() {
    	LinkedList<Integer> list = be.revokedLists();
    	// Do something with the returned lists to see if it is okay
    	return true;
    }
    
    Boolean testSomeOtherMethod() {
    	// SomeRV rv = be.someOtherMethod();
    	// Do some testing to check if someOtherMethod does the right thing
    	// return false if it is wrong
    	return true;
    }
    
    Boolean testCertificateCreation(){
    	return true;
    }
    
    Boolean testKeyCreation(){
    	be.RSAKeyGen();
    	PrivateKey priv = be.RSAKeyGen().getPrivate();
    	PublicKey pub = be.RSAKeyGen().getPublic();
    	System.out.println(priv);
    	return true;
    }
}