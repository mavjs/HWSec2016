/*
 * Based on http://www.cs.ru.nl/~erikpoll/hw/samples/ChipknipTerminal.java, 
 * Freed from JCOP libraries by porting it to javax.smartcardio.* ;-)
 */

import java.util.List;

import javax.smartcardio.Card;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.CardTerminals;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import javax.smartcardio.TerminalFactory;

public class ChipknipTerminal {
	private static CommandAPDU GET_BALANCE_APDU = new CommandAPDU(
			(byte) 0xE1, (byte) 0xB4, (byte) 0x00, (byte) 0x01, null, 5);

	public ChipknipTerminal() {
	    try {
	    	TerminalFactory tf = TerminalFactory.getDefault();
	    	CardTerminals ct = tf.terminals();
	    	List<CardTerminal> cs = ct.list(CardTerminals.State.CARD_PRESENT);
	    	if (cs.isEmpty()) {
	    		System.err.println("No terminals with a card found.");
	    		return;
	    	}
	    	
	    	for(CardTerminal c : cs) {
	    		if (c.isCardPresent()) {
	    			try {
	    				Card card = c.connect("*");
	    				try {
	    					CardChannel ch = card.getBasicChannel();
	    					ResponseAPDU resp = ch.transmit(GET_BALANCE_APDU);
	    					String balance = amountString(getBalance(resp));
	    					System.out.println("Chipknip balance: "	+ balance);
	    				} catch (Exception e) {
	    					System.err.println("Card is not a Chipknip?!");
	    				}
	    				card.disconnect(false);
	    			} catch (CardException e) {
	    				System.err.println("Couldn't connect to card!");
	    			}
	    			return;
	    		} else {
	    			System.err.println("No card present!");
	    		}
	    	}
    	} catch (CardException e) {
    		System.err.println("Card status problem!");
	    }
	}

	public static int getBalance(ResponseAPDU ra) {
		byte[] data = ra.getBytes();
		return ((data[0] & 0x000000FF) << 16) | ((data[1] & 0x000000FF) << 8)
				| (data[2] & 0x000000FF);
	}

	private static String amountString(int value) {
		return (value / 100) + "." + (((value % 100) < 10) ? "0" : "")
				+ (value % 100);
	}

	public static void main(String[] arg) {
		new ChipknipTerminal();
	}
}
