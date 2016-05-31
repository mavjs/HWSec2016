package baseterminal;

import java.nio.ByteBuffer;
import java.security.KeyPair;
import java.util.Arrays;
import java.util.List;
import java.util.Scanner;
import backend.Storage;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.smartcardio.Card;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.CardTerminals;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import javax.smartcardio.TerminalFactory;

public class Terminal implements GlobalVariables {

	protected CommandAPDU SELECT_APPLET = new CommandAPDU(
			(byte) 0x00, (byte) 0xA4, (byte) 0x04, (byte) 0x00, AID);
	protected CommandAPDU ISSUE_CARD = new CommandAPDU(CLA_UNENCRYPTED, INS_ISSUE, (byte) 0x00, (byte) 0x00);
	protected CommandAPDU UNISSUE_CARD = new CommandAPDU(CLA_UNENCRYPTED, INS_UNISSUE, (byte) 0x00, (byte) 0x00);
    final byte[] keyBytes = {(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00}/*Arrays.copyOf(digestOfPassword,24)*/;
	
	protected Card card = null;
	protected CardChannel channel = null;
	protected Scanner scanner = null;
	
	
	/*
	 * Constructor
	 */
	public Terminal() {
		this.scanner = new Scanner(System.in);
		this.doConnectToCard();	
	}
	
	
	/*
	 * Ask the pincode
	 */
	protected byte[] doAskPIN() {
		System.out.println("Enter PIN(4 char): "); 
	    short iPIN = 0;
	    while (iPIN == 0) {
	    	try {
	    		iPIN = this.scanner.nextShort();
		    }
		    catch(Exception e) {}
	    }
	
	    ByteBuffer buffer = ByteBuffer.allocate(2);
	    buffer.putShort(iPIN);
	    return buffer.array();
	}
	
	
	/*
	 * Waits until terminal and card is found, connects to the card
	 * Callback to onChannelCreated
	 */
	protected void doConnectToCard() {
		try {
			//List terminals
	    	TerminalFactory tf = TerminalFactory.getDefault();
	    	CardTerminals ct = tf.terminals();
	    	List<CardTerminal> cs = ct.list(CardTerminals.State.CARD_PRESENT);
	    	
	    	//Wait for terminal with inserted card
	    	while (cs == null || cs.isEmpty()) {
	    		try {
					Thread.sleep(1000);
				} catch (Exception e) {
					
				}
	    		cs = ct.list(CardTerminals.State.CARD_PRESENT);
	    		System.out.println("No terminals with a card found.");
	    	}
	    	
	    	//Lookup card
	    	for(CardTerminal c : cs) {
	    		
	    		//When card is found, try to connect and establish base channel
	    		if (c.isCardPresent()) {
	    			try {
	    				this.card = c.connect("*");
	    				this.channel = null;
	    				try {
	    					this.channel = card.getBasicChannel();
	    				} catch (Exception e) {
	    					System.out.println("Could not establish a channel with the card");
	    				}
	    				//If channel has been established, call onChannelCreated
	    				if(this.channel != null)
	    					this.onChannelCreated();
	    				
	    			} catch (CardException e) {
	    				System.out.println("Could not connect to card!");
	    			}
	    		} else {
	    			System.out.println("No card present!");
	    		}
	    	}
    	} catch (CardException e) {
    		System.out.println("Card status problem!");
	    }
	}
	
	
	private ResponseAPDU doDecryptAPDU(ResponseAPDU apdu) {
		//TODO Do decryption stuff
		System.out.println("Start decryption for Response with SW:" + Integer.toHexString(apdu.getSW()));
		byte[] plainText = {};
		try {
	
	    	final SecretKey key = new SecretKeySpec(keyBytes, "DESede");
	    	final IvParameterSpec iv = new IvParameterSpec(new byte[8]);
	    	final Cipher decipher = Cipher.getInstance("DESede/CBC/NoPadding");
	    	decipher.init(Cipher.DECRYPT_MODE, key, iv);
	
	    	plainText = decipher.doFinal(apdu.getData());
		}
		catch (Exception e){
			System.out.println("Decryption failed... " + e.toString());
		}
		
		System.out.println("PLain before copy " + ": " + new String(plainText));
		byte[] fakerapdu = Arrays.copyOf(plainText, plainText.length + 2);
		
		fakerapdu[plainText.length+0] = (byte) apdu.getSW1();
		fakerapdu[plainText.length +1] = (byte) apdu.getSW2();
		return new ResponseAPDU(fakerapdu);		
	}
	
	
	
	/*
	 * Disconnects from card 
	 */
	protected void doDisconnectCard() {
		if(this.card == null)  return;
		try {
			this.card.disconnect(false);
		} catch(CardException e) {
			System.out.println("Card disconnect failed!");
		}
	}
	
	
	/*
	 * Encrypts the APDU
	 */
	private CommandAPDU doEncryptAPDU(CommandAPDU apdu) {
        System.out.println("Start Encryption for apdu with INS: " + Integer.toHexString(apdu.getINS()));
        byte[] cipherText = {};
        try {
            final SecretKey key = new SecretKeySpec(this.keyBytes, "DESede");
            final IvParameterSpec iv = new IvParameterSpec(new byte[8]);
            final Cipher cipher = Cipher.getInstance("DESede/CBC/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, key, iv);
       
            cipherText = cipher.doFinal(apdu.getData());
        }
        catch (Exception e){
        System.out.println("Encryption failed... " + e.toString());
        }
       
       
        return new CommandAPDU(apdu.getCLA(), apdu.getINS(), apdu.getP1(), apdu.getP2(), cipherText);
	}
	
	
	/*
	 * Retrieves balance
	 */
	protected short doGetBalance() {
		CommandAPDU apdu = new CommandAPDU(CLA_ENCRYPTED, INS_BALANCE_GET, 0x00, 0x00);
		ResponseAPDU rapdu = this.doTransmit(apdu);
		if(rapdu == null || rapdu.getSW() != 0x9000)
			return -1;
		return rapdu.getData()[0];	
	}
	

	/*
	 * Terminal sepcific communication
	 */
	protected void doSecureCommunication() {
		//Implement in child classes
	}
	
    /*
    * Get keys
    */
    protected KeyPair doGetKeys() {
    //TODO: Get keypair from files
    return null;
    }
	
	/*
	 * Sends apdu to select applet
	 */
	protected boolean doSelectApplet() {
		ResponseAPDU rapdu = this.doTransmit(SELECT_APPLET);
		if(rapdu == null || rapdu.getSW() != 0x9000)
			return false;
		return true;	
	}
	
	
	/*
	 * Transmits APDU
	 */
	protected ResponseAPDU doTransmit(CommandAPDU apdu) {
		if(apdu == null) return null;
		
		boolean bEncrypted = apdu.getCLA() == CLA_ENCRYPTED;
		try {
			if(bEncrypted)
				this.doEncryptAPDU(apdu);
			
			ResponseAPDU rapdu = this.channel.transmit(apdu);
			
			if(bEncrypted)
				return this.doDecryptAPDU(rapdu);
			
			return rapdu;
		}
		catch (CardException e) {
			System.out.println("Transmitting APDU failed");
		}
		return null;
		
	}
	
	
	/*
	 * Verifies the PINCODE
	 */
	protected boolean doVerifyPIN() {	
		System.out.println("#Verifying PIN ");
	    byte[] aPin = this.doAskPIN();
	    CommandAPDU apdu = new CommandAPDU(CLA_ENCRYPTED, INS_PIN_VERIFY, 0x00, 0x00,aPin);
	    
	    ResponseAPDU rapdu = this.doTransmit(apdu);
		if(rapdu != null && rapdu.getSW() == 0x9000) {
			System.out.println("PIN is correct");
			return true;
		}
		else if(rapdu != null && rapdu.getSW() == 0x6303) {
			System.out.println("PIN is incorrect");
		}
		else {
			System.out.println("PIN Could not be verfied ");
			
		}	
		return false;	
	}
	
	
	/*
	 * Called from doConnectToCard, default implementation for petrol and charging terminal
	 * Init terminal has own implementation
	 */
	protected void onChannelCreated() {
		//Select applet
		if(!this.doSelectApplet())
			return;
		
		//TODO set up mutual authentication and shared key
        KeyPair keypair = this.doGetKeys();
        //TODO: Send pub key to card
        // Get pubkey from card in response data
        // request symmetric key from card encrypted by cards priv key
        // decrypt with cards pub key
        //init DES3 with symmm key
		
		//PIN verification
		if(!this.doVerifyPIN()) {
			return;
		}
	
		this.doSecureCommunication();
		this.doDisconnectCard();
	}
}
