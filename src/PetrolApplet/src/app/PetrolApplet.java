package app;

import javacard.security.*;
import javacardx.crypto.*;

import javacard.framework.*;


/**
 * 
 * @author Group 2!
 *
 * APDU Structure cheat sheet:
 *   CLA (1 byte): Class of instruction --- indicates the structure and format for a category of command and response APDUs
 *   INS (1 byte): Instruction code: specifies the instruction of the command
 *   P1 (1 byte) and P2 (1 byte): Instruction parameters -- further provide qualifications to the instruction
 *   Lc (1 byte): Number of bytes present in the data field of the command
 *   Data field (bytes equal to the value of Lc): A sequence of bytes in the data field of the command
 *   Le (1 byte): Maximum of bytes expected in the data field of the response to the command 
 */

public class PetrolApplet extends javacard.framework.Applet implements ISO7816 {
    // Classes go here
    /** For encrypted instructions and responses */
    static final byte CLA_PROTECTED_APDU = 0x0c;
    
    // Instructions go here
    /* Not yet issued */
    private static final byte INS_SET_ID = (byte)0x00;
    private static final byte INS_ISSUE = (byte)0x10;
    private static final byte INS_PIN_SET = (byte)0x20;
    private static final byte INS_UNISSUE = (byte)0x11;

    private static final byte INS_STORE_BACKEND_CERT = (byte)0x40;
    private static final byte INS_STORE_CARD_CERT = (byte)0x50;
    
    /* Issued */
    private static final byte INS_PIN_VERIFY = (byte)0x21;
    private static final byte INS_BALANCE_GET = (byte)0x30;
    private static final byte INS_BALANCE_SUB = (byte)0x31;
    private static final byte INS_RECV_VERIFY_TERM_CERT = (byte)0xa0;


    // TODO This does leak information about where in the protocol things fail, but it is nice for debugging to have it for now
    // Errors go here
    private final static short SW_WRONG_CERTIFICATE_LENGTH = 0x6a00;
    private final static short SW_WRONG_CERTIFICATE = 0x6a01;
    
    private final static short SW_PIN_VERIFICATION_REQUIRED = 0x6301;
    private final static short SW_WRONG_PIN_LENGTH = 0x6302;
    private final static short SW_WRONG_PIN = 0x6303;


    // Variables go here
    
    private static final byte STATE_INIT = (byte)0x00;
    private static final byte STATE_ISSUED = (byte)0x01;
    
    /** Temporary buffer in RAM, clear on reset */
    byte[] tmp;
       
    /** The applet state (INIT or ISSUED). */
    byte state;
    
    /** Key for encryption. */
    RSAPublicKey pubKeyCard;

    /** Key for decryption. */
    RSAPrivateKey privKeyCard;
    
    /** Backend key for encryption */
    RSAPublicKey pubKeyBackEnd;

    /** Cipher for encryption and decryption. */
    Cipher cipher;
    
    /** Pincode */
    OwnerPIN pin;
    /** maximum number of incorrect tries before the PIN is blocked TODO How many? */
    final static byte PinTryLimit =(byte)0x7f; // Careful this is a signed value and negative will prevent the applet from installing
    /** maximum size PIN, in bytes */
    final static byte MaxPinSize =(byte)0x02;

    
    /** Balance of the card, maximum of 32767 TODO: Higher */
    short cardBalance;
    
    /** Personal ID */
    short id;
    
    /** The root certificate, contains the root public key which we will need for certificate validation */
    CVCertificate certificateRoot;
    /** Cards CVC Certificate, signed by the CA (Probably the back end) */
    CVCertificate certificateCard;
    /** During mutual authentication we will receive a terminal certificate */
    CVCertificate certificateTerminal;
    

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        // GP-compliant JavaCard applet registration
        new PetrolApplet().register(bArray, (short) (bOffset + 1),
                bArray[bOffset]);
    }
    
    /** Constructor at applet-install-time; creates the key-structure and sets the state to STATE_INIT
     * this is the only time we can create new data structures, so make it count.
     */
    public PetrolApplet() {
        /** Transient array in RAM to use for 'things' (what? Maybe first byte: isAtThisStepOfMutualAuthProtocol */
        tmp = JCSystem.makeTransientByteArray((short)256,JCSystem.CLEAR_ON_RESET);
        /** Card will establish a session key, store here */
        //cipher = Cipher.getInstance(Cipher.ALG_RSA_PKCS1_OAEP,false);
        
        /** Things in EEPROM */
        /** When the applet is installed the state is STATE_INIT */
        state = STATE_INIT;
        /** Public key of the card, this should be in a X509/CVC structure. But I don't know how that works yet */
        // TODO Discuss ECC for size
        pubKeyCard = (RSAPublicKey)KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, KeyBuilder.LENGTH_RSA_1024,false);
        /** Cards own private key */
        privKeyCard = (RSAPrivateKey)KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PRIVATE, KeyBuilder.LENGTH_RSA_1024,false);
        /** Public key of the back end, this should eventually be in a X509 structure. */
        pubKeyBackEnd = (RSAPublicKey)KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, KeyBuilder.LENGTH_RSA_1024,false);
        /** The revocation list */
        // TODO
        /** The pin structure */
        pin = new OwnerPIN(PinTryLimit, MaxPinSize);
        /** Initial balance is zero */
        cardBalance = (short)0x1337;
        /** Logging? */
        // Log log = new log;
        /** Certificates */
        certificateRoot = new CVCertificate();
        certificateCard = new CVCertificate();
        certificateTerminal = new CVCertificate();
    }
    
    public void deselect() {
        /** If pin was validated this resets the validation and counter, else does nothing */
        pin.reset();
    }
    
    public boolean select() {
        /** Decline selection if blocked */
        if ( pin.getTriesRemaining() == 0 ) return false;
        return true;
    }

    public void process(APDU apdu) {
        // Good practice: Return 9000 on SELECT
        byte[] buffer = apdu.getBuffer();
        short cla = (short) (buffer[OFFSET_CLA] & 0xff); 
        short ins = (short) (buffer[OFFSET_INS] & 0xff);
        short lc =  (short) (buffer[OFFSET_LC] & 0xff);

        short outLength;

        //boolean protectedApdu = (byte)(cla & CLA_PROTECTED_APDU)  == CLA_PROTECTED_APDU;
        
        if (selectingApplet()) {
            return;
        }
      
        switch(state) {
        /* The card is not yet initialized, there will need to be support for:
         * - Uploading key material
         * - Uploading card identification
         * - Set pin code
         * - (Register to car owner)
         * - Setting the state to issued.
         */
        case STATE_INIT:
            switch(ins){
            /** I read that every card already has an unique ID in it at physical-creation-time, maybe look into that */
            case INS_SET_ID:
                setID();
                break;
            /** Receive and store card certificate */
            case INS_STORE_CARD_CERT:
                setCardCertificate(apdu);
                break;
            /** During initialization we receive the back-end (r00t) certificate, to verify terminal certificates with */
            case INS_STORE_BACKEND_CERT:
                setBackEndCert(apdu);
                break;
            /** Set the pin */
            case INS_PIN_SET:
                setPin(apdu);
                break;
            /** Issue the card, can not be undone */
            case INS_ISSUE:
                issueCard();
                break;
            default:
                ISOException.throwIt(SW_INS_NOT_SUPPORTED);
            }
            break;
        /* The card has been initialized, all the key material is assumed to be present.
         * Support for:
         * Charging terminal:
         * - Validate card
         * - PIN validation
         * - View balance
         * - Charge rations
         * Petrol terminal:
         * - View petrol allowance (different types?)
         * - Decrease balance (to 0)
         * - Increase (Write back)
         * EOL
         * - More relevant at infrastructure level, but maybe:
         * Stolen:
         * - If card number is reported as stolen the card will activate the alarm bells installed
         * at every terminal and automatically call the police. 
         */
        case STATE_ISSUED:
            switch(ins) {
            case INS_PIN_VERIFY:
                pin_verify(apdu);
                break;
            case INS_UNISSUE:
                unIssueCard();
                break;
            case INS_BALANCE_GET:
                getBalance(apdu);
                break;
            case INS_BALANCE_SUB:
                subBalance(apdu);
                break;
            case INS_RECV_VERIFY_TERM_CERT:
                receiveAndVerifyTermCert(apdu);
                break;
            default:
                ISOException.throwIt(SW_INS_NOT_SUPPORTED);
            }
            break;
        }
    }

    private void subBalance(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        byte byteRead = (byte)(apdu.setIncomingAndReceive());

        if(byteRead != (byte) 2)
            ISOException.throwIt ( (short) 0xabcd);
        
        // get the amount from the buffer
        short s = 0;
        s = (short) (buffer[ISO7816.OFFSET_CDATA] << 8);
        s +=(short) (buffer[ISO7816.OFFSET_CDATA+1]);
        if( s > cardBalance)
            ISOException.throwIt((short) 0x1234);
        cardBalance = (short) (cardBalance - s);
        return;
    }

    private void setBackEndCert(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        short buffer_p = (short) (OFFSET_CDATA & 0xff); // fancy way to write 5
        byte byteRead = (byte)(apdu.setIncomingAndReceive());
        
        /** This is the root certificate for the system" */
        //Util.arrayCopyNonAtomic(buffer, buffer_p, certroot, (short) 0, byteRead);  // certroot = buffer;
        certificateCard.parseCertificate(buffer, buffer_p, byteRead, true);
        return;
    }

    /** During mutual authentication we receive a certificate, we shall
     *  verify that this certificate is signed by the CA. We can then
     *  use the public key from this certificate for the mutual
     *  authentication protocol. */
    private void receiveAndVerifyTermCert(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        short buffer_p = (short) (OFFSET_CDATA & 0xff);
        byte byteRead = (byte)(apdu.setIncomingAndReceive());
        
        /** Card certificate is signed by the "Overall System acting as CA" */
        certificateTerminal.parseCertificate(buffer, buffer_p, byteRead, false);
        // Somehow set the public key to be used for verification
        //certificateTerminal.setRootCertificate(certroot, (short)1); //TODO dear god
        // Idea: store the byte[] of certificateRoot only... we might not need to parse it... ever... maybe
        // Do the actual signature verification
        if(!certificateTerminal.verify()){
            ISOException.throwIt(SW_WRONG_CERTIFICATE); 
        }
        return;
    }

    private void getBalance(APDU apdu) {
        if ( !pin.isValidated()){ ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED); }
        
        byte[] buffer = apdu.getBuffer();
        short le = apdu.setOutgoing();
        if ( le < 2 ) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
      
      
        //informs the CAD the actual number of bytes returned
        apdu.setOutgoingLength((byte)2);
      
        // move the balance data into the APDU buffer
        // starting at the offset 0
        buffer[0] = (byte)(cardBalance >> 8);
        buffer[1] = (byte)(cardBalance & 0xFF);
        // send the 2-balance byte at the offset
        // 0 in the apdu buffer
        apdu.sendBytes((short)0, (short)2);
        return;
    }

    private void pin_verify(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        // retrieve the PIN data to validate.
        byte byteRead = (byte)(apdu.setIncomingAndReceive());

        // Die if PinSize is not correct (information leak?)
        if (byteRead != MaxPinSize){
            ISOException.throwIt(SW_WRONG_PIN_LENGTH);
        }
        // Set the pin to the value in the data field
        if (pin.check(buffer, ISO7816.OFFSET_CDATA,byteRead)){
            return;
        }
        ISOException.throwIt(SW_WRONG_PIN);
    }

    private void setID() {
        // TODO Auto-generated method stub
    }
    
    /** For debugging purposes, remove before production. */
    private void unIssueCard() {
        state = STATE_INIT;
        return;
    }
    
    
    private void issueCard() {
        state = STATE_ISSUED;
        return;
    }

    /** Set the cards own CVC certificate during initialization */
    private void setCardCertificate(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        short buffer_p = (short) (OFFSET_CDATA & 0xff);
        byte byteRead = (byte)(apdu.setIncomingAndReceive());
        
        /** Card certificate is signed by the "Overall System acting as CA" */
        
        //certroot = buffer;
        certificateCard.parseCertificate(buffer, buffer_p, byteRead, true);
    }
    
    // Could also be done at install-time
    /** Sets the PIN code of a card */
    private void setPin(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        // retrieve the PIN data.
        byte byteRead = (byte)(apdu.setIncomingAndReceive());
        
        // Die if PinSize is not correct
        if (byteRead != MaxPinSize){
            ISOException.throwIt(SW_WRONG_PIN_LENGTH);
        }
        // Set the pin to the value in the data field
        pin.update(buffer, ISO7816.OFFSET_CDATA,byteRead);
        return;
    }
} // End of class
