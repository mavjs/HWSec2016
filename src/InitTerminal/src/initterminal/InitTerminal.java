package initterminal;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import baseterminal.Terminal;



public class InitTerminal extends Terminal {
	
	
	
	
	
	public InitTerminal() {
		super();
	}

	/**
	 * @param args
	 */
	public static void main(String[] args) {
		new InitTerminal();
	}

	
	/*
	 * Sets card issued flag 
	 */
	private void doSetIssued() {
		ResponseAPDU rapdu = this.doTransmit(ISSUE_CARD);
		if(rapdu != null && rapdu.getSW() == 0x9000)
			System.out.println("Card has been set to issued ");
		else if(rapdu != null && rapdu.getSW() == 0x6300)
			System.out.println("Instruction not found (Card probably has already been set to issued) ");
		else {
			System.out.println("Card could not been set to issued. SW " + Integer.toHexString(rapdu.getSW()));
		}
	}
	
	
	/*
	 * Remove card issued flag 
	 */
	private void doSetUnIssued() {
		ResponseAPDU rapdu = this.doTransmit(UNISSUE_CARD);
		if(rapdu != null && rapdu.getSW() == 0x9000)
			System.out.println("Card has been set to not issued ");
		else if(rapdu != null && rapdu.getSW() == 0x6300)
			System.out.println("Instruction not found (Card probably has already been set to unissued) ");
		else {
			System.out.println("Card could not been set to unissued. SW " + Integer.toHexString(rapdu.getSW()));
		}
	}
	
	/*
	 * Set the PINCODE
	 */
	private boolean doSetPIN() {	

	    byte[] aPin = this.doAskPIN();
	    CommandAPDU apdu = new CommandAPDU(CLA_ENCRYPTED, INS_PIN_SET, 0x00, 0x00,aPin);
	    
	    ResponseAPDU rapdu = this.doTransmit(apdu);
		if(rapdu != null && rapdu.getSW() == 0x9000) {
			System.out.println("PIN set");
			return true;
		}
		else if(rapdu != null && rapdu.getSW() == 0x6302) {
			System.out.println("PIN Could not be set, length incorrect");
		}
		else {
			System.out.println("PIN Could not be set ");
			
		}	
		return false;	
	}
	
	
	
	
	/*
	 * Called from doConnectToCard overrides default
	 */
	protected void onChannelCreated() {
		//Select applet
		if(!this.doSelectApplet())
			return;
		this.doSetUnIssued();
		System.out.println("#Setting PIN ");
		if(this.doSetPIN())
			this.doSetIssued();
		this.doVerifyPIN();
		
		
		CommandAPDU apdu = new CommandAPDU(CLA_ENCRYPTED, 0x41, 0x00, 0x00);
	    
	    ResponseAPDU rapdu = this.doTransmit(apdu);
	    System.out.println("Decryption SW " + Integer.toHexString(rapdu.getSW()) + ": " + new String(rapdu.getData()));
	    this.doDisconnectCard();
		System.out.println("Card issue complete, pull out your card. ");
		
	}
}