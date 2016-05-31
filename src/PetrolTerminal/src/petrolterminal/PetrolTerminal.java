package petrolterminal;

import java.nio.ByteBuffer;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import baseterminal.Terminal;



public class PetrolTerminal extends Terminal {
	
	
	public PetrolTerminal() {
		super();
	}

	/**
	 * @param args
	 */
	public static void main(String[] args) {
		new PetrolTerminal();
	}
	
	
	
	/*
	 * Terminal specific communication
	 */
	protected void doSecureCommunication() {
		System.out.println("Current balance is: " + this.doGetBalance());
		
		System.out.println("Enter amount of fuel you would like to withdraw: "); 
	    short iAmount = -1;
	    while (iAmount == -1) {
	    	try {
	    		iAmount = this.scanner.nextShort();
		    }
		    catch(Exception e) {}
	    }
	    
	    
	    while(!this.doSubtractBalance(iAmount)) {
	    	System.out.println("Enter amount of fuel you would like to withdraw: "); 
	    	iAmount = -1;
		    while (iAmount == -1) {
		    	try {
		    		iAmount = this.scanner.nextShort();
			    }
			    catch(Exception e) {}
		    }
	    }
	    
	    System.out.println("Current balance is: " + this.doGetBalance());
	}
	
	
	/*
	 * Subtracts balance
	 */
	protected boolean doSubtractBalance(short iAmount) {
		
		ByteBuffer amountBuffer = ByteBuffer.allocate(2);
		amountBuffer.putShort(iAmount);
		
		CommandAPDU apdu = new CommandAPDU(CLA_ENCRYPTED, INS_BALANCE_SUB, 0x00, 0x00, amountBuffer.array());
		ResponseAPDU rapdu = this.doTransmit(apdu);
		if(rapdu != null && rapdu.getSW() == 0x9000) {
			System.out.println("Balance subtracted");
			return true;
		}
		else if(rapdu != null && rapdu.getSW() == 0x1234) {
			System.out.println("Balance too low to be subtracted");
		}
		else if (rapdu != null)
			System.out.println("Balance could not be subtracted. SW " + Integer.toHexString(rapdu.getSW()));
		
		return false;
			
	}
	
	
	

}
