package baseterminal;

public interface GlobalVariables {
	public static final byte CLA_UNENCRYPTED =  (byte) 0x40;
	public static final byte CLA_ENCRYPTED =  (byte) 0x41;
	
	public static final byte INS_ISSUE =  (byte) 0x10;
	public static final byte INS_UNISSUE =  (byte) 0x11;
	public static final byte INS_PIN_SET =  (byte) 0x20;
	public static final byte INS_PIN_VERIFY =  (byte) 0x21;
	public static final byte INS_BALANCE_GET =  (byte) 0x30;
	public static final byte INS_BALANCE_SUB = (byte) 0x31;
	public static final byte INS_BALANCE_INC = (byte) 0x32;
	
	public static final byte[] AID = { (byte) 0xCA, (byte) 0xFE,
        (byte) 0xEB, (byte) 0xAB, (byte) 0xEE, (byte) 0x02 };
}
