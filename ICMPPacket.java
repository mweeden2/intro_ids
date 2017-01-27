/*
 * ICMP Packet
 * 2/3/16 - 3/15/16
 * 
 * by Matt Weeden
 * 
 * CS 7473 Network Security
 * Dr. Mauricio Papa
 * 
 */

import java.util.Arrays;

public class ICMPPacket extends IPPacket{


	private byte[] ICMPtype;
	private byte[] ICMPcode;
	private byte[] ICMPchecksum;
	private byte[] ICMPpayload;

	private String ICMPtypeString;
	private String ICMPcodeString;
	private String ICMPchecksumString;
	private String ICMPpayloadString;

	private int ICMPpayloadLengthI;

	public ICMPPacket(byte[] bs) {
		super(bs);
	}

	public String parseICMP () {
		String outputS = "";

		outputS += super.parseIP();

		if (getIPpayload().length<8) {
			//outputS += "\nThis packet's ICMP header isn't long enough.\n\n";
		}
		else {
			ICMPtype = Arrays.copyOfRange(getIPpayload(), 0, 1);
			ICMPcode = Arrays.copyOfRange(getIPpayload(), 1, 2);
			ICMPchecksum = Arrays.copyOfRange(getIPpayload(), 2, 4);

			ICMPtypeString = getDriver().byteArrayToString(ICMPtype).substring(0, 2);
			ICMPcodeString = getDriver().byteArrayToString(ICMPcode).substring(0, 2);
			ICMPchecksumString = getDriver().byteArrayToString(ICMPchecksum).substring(0, 5);

			// get payload based on IP payload length
			ICMPpayloadLengthI = getIPpayloadLengthI() - 4;
			if (ICMPpayloadLengthI>0) {
				ICMPpayload = Arrays.copyOfRange(getIPpayload(), 4, getIPpayloadLengthI());
				ICMPpayloadString = "";
				for (int i=0; i<ICMPpayload.length; i++) {
					ICMPpayloadString += getDriver().byteToHex(ICMPpayload[i])+" ";
				}
			}
		}
		return outputS;
	}

	public void printICMPrawParse () {
		if (ICMPtype==null) {
			System.out.println("ICMP packet not parsed.");
		}
		else {
			System.out.println("ICMPtype: "+ICMPtypeString);
			System.out.println("ICMPcode: "+ICMPcodeString);
			System.out.println("ICMPchecksum: "+ICMPchecksumString);
			if (ICMPpayloadLengthI>0) {
				System.out.println("IPpayload (length="+ICMPpayloadLengthI+"):\n"+
						ICMPpayloadString);
			}
			else {
				System.out.println("There is no ICMP payload.");
			}
		}
	}

	public String ICMPprettyParse () {
		String parseS = "";
		parseS += "\nICMP\n"
				+ "==================================\n";
		if (ICMPtype==null) {
			parseS += "ICMP packet not parsed.\n";
		}
		else {
			// classify type of ICMP packet
			if (Integer.parseInt(ICMPtypeString, 16) == 0) {
				parseS += "type: echo reply (0)\n";
			}
			else if (Integer.parseInt(ICMPtypeString, 16) == 3) {
				parseS += "type: destination unreachable (3)\n";
			}
			else if (Integer.parseInt(ICMPtypeString, 16) == 4) {
				parseS += "type: source quench (4)\n";
			}
			else if (Integer.parseInt(ICMPtypeString, 16) == 5) {
				parseS += "type: redirect message (5)\n";
			}
			else if (Integer.parseInt(ICMPtypeString, 16) == 8) {
				parseS += "type: echo request (8)\n";
			}
			else if (Integer.parseInt(ICMPtypeString, 16) == 11) {
				parseS += "type: time exceeded (11)\n";
			}
			else if (Integer.parseInt(ICMPtypeString, 16) == 12) {
				parseS += "type: parameter problem (12)\n";
			}
			else if (Integer.parseInt(ICMPtypeString, 16) == 13) {
				parseS += "type: timestamp request (13)\n";
			}
			else if (Integer.parseInt(ICMPtypeString, 16) == 14) {
				parseS += "type: timestamp reply (14)\n";
			}
			else if (Integer.parseInt(ICMPtypeString, 16) == 17) {
				parseS += "type: address mask request (17)\n";
			}
			else if (Integer.parseInt(ICMPtypeString, 16) == 18) {
				parseS += "type: address mask reply (18)\n";
			}
			else {
				parseS += "type: "+Integer.parseInt(ICMPtypeString, 16)+"\n";
			}
			
			parseS += "code: "+Integer.parseInt(ICMPcodeString, 16)+"\n";
			parseS += "checksum: "+Integer.parseInt
					(ICMPchecksumString.replaceAll("\\s", ""), 16)+"\n";
			parseS += "ICMPpayload length: "+ICMPpayloadLengthI+"\n";
			if (ICMPpayloadLengthI>0) {
				parseS += "ICMPpayload:\n"+
						getDriver().byteArrayToString(ICMPpayload)+"\n";
			}
			else {
				parseS += "There is no ICMP payload.\n";
			}
		}
		return parseS;
	}

	public byte[] getICMPtype() {
		return ICMPtype;
	}

	public void setICMPtype(byte[] iCMPtype) {
		ICMPtype = iCMPtype;
	}

	public byte[] getICMPcode() {
		return ICMPcode;
	}

	public void setICMPcode(byte[] iCMPcode) {
		ICMPcode = iCMPcode;
	}

	public byte[] getICMPchecksum() {
		return ICMPchecksum;
	}

	public void setICMPchecksum(byte[] iCMPchecksum) {
		ICMPchecksum = iCMPchecksum;
	}

	public byte[] getICMPpayload() {
		return ICMPpayload;
	}

	public void setICMPpayload(byte[] iCMPpayload) {
		ICMPpayload = iCMPpayload;
	}

	public String getICMPtypeString() {
		return ICMPtypeString;
	}

	public void setICMPtypeString(String iCMPtypeString) {
		ICMPtypeString = iCMPtypeString;
	}

	public String getICMPcodeString() {
		return ICMPcodeString;
	}

	public void setICMPcodeString(String iCMPcodeString) {
		ICMPcodeString = iCMPcodeString;
	}

	public String getICMPchecksumString() {
		return ICMPchecksumString;
	}

	public void setICMPchecksumString(String iCMPchecksumString) {
		ICMPchecksumString = iCMPchecksumString;
	}

	public String getICMPpayloadString() {
		return ICMPpayloadString;
	}

	public void setICMPpayloadString(String iCMPpayloadString) {
		ICMPpayloadString = iCMPpayloadString;
	}

	public int getICMPpayloadLengthI() {
		return ICMPpayloadLengthI;
	}

	public void setICMPpayloadLengthI(int iCMPpayloadLengthI) {
		ICMPpayloadLengthI = iCMPpayloadLengthI;
	}
}
