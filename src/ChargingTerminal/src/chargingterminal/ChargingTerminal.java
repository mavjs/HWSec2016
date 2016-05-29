package chargingterminal;

import java.nio.ByteBuffer;
import java.util.Calendar;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import baseterminal.Terminal;


public class ChargingTerminal extends Terminal {
	
	
	public ChargingTerminal() {
		super();
	}

	/**
	 * @param args
	 */
	public static void main(String[] args) {
		new ChargingTerminal();
	}
	
	
	/*
	 * Terminal specific communication
	 */
	protected void doSecureCommunication() {
		short iAllowance = (short) 40;
		
		System.out.println("Current balance is: " + this.doGetBalance());
		System.out.println("#Updating with montly allowance: "+iAllowance);
	    
		this.doAddBalance(iAllowance);
	    
	    System.out.println("Updated balance is: " + this.doGetBalance());
	}
	
	
	/*
	 * Adds balance
	 */
	protected boolean doAddBalance(short iAmount) {
		Calendar now = Calendar.getInstance();
		
		ByteBuffer amountBuffer = ByteBuffer.allocate(8);
		amountBuffer.putShort(iAmount);
		amountBuffer.putShort((short)now.get(Calendar.YEAR));
		amountBuffer.putShort((short)now.get(Calendar.MONTH));
		amountBuffer.putShort((short)now.get(Calendar.DAY_OF_MONTH));
		
		CommandAPDU apdu = new CommandAPDU(CLA_ENCRYPTED, INS_BALANCE_INC, 0x00, 0x00, amountBuffer.array());
		ResponseAPDU rapdu = this.doTransmit(apdu);
		if(rapdu != null && rapdu.getSW() == 0x9000) {
			System.out.println("Balance updated");
			return true;
		}
		else if(rapdu != null && rapdu.getSW() == 0xdead) {
			System.out.println("You have already charged this month, charging cancelled");
		}
		else if(rapdu != null && rapdu.getSW() == 0x1234) {
			System.out.println("Incorrect allowance (either your balance is getting to high or the allowance is negative)");
		}
		else if (rapdu != null)
			System.out.println("Balance could not be updated. SW " + Integer.toHexString(rapdu.getSW()));
		
		return false;
			
	}
	
	
	
	

}