/*
 * Ethernet Packet
 * 2/3/16 - 3/15/16
 * 
 * by Matt Weeden
 * 
 * CS 7473 Network Security
 * Dr. Mauricio Papa
 * 
 */

import java.util.Arrays;

public class EthernetPacket extends Packet {

	private byte[] dstMAC;
	private byte[] srcMAC;
	private byte[] etherType;
	private byte[] ethPayload;
	private byte[] CRCchecksum;

	private String dstMACstring;
	private String srcMACstring;
	private String etherTypeString;
	private String ethPayloadString;
	// the CRC checksum is assumed to be removed before presented to this parser
	
	private int ethPayloadLength;

	////////////////////////////////////////////////////////////////////////////////////////////////
	public EthernetPacket(byte[] bs) {
		super(bs);
	}

	public String parseEthernet() {
		
		String outputS = "";
		
		if (getBytes().length<20) {
			//outputS += "\nThis packet's Ethernet header isn't long enough.\n\n";
		}
		else {
			dstMAC = Arrays.copyOfRange(getBytes(), 0, 6);
			srcMAC = Arrays.copyOfRange(getBytes(), 6, 12);
			etherType = Arrays.copyOfRange(getBytes(), 12, 14);
			ethPayload = Arrays.copyOfRange(getBytes(), 14, getPacketLengthInBytes());
			ethPayloadLength = ethPayload.length;

			dstMACstring = getDriver().byteArrayToString(dstMAC).substring(0, 17);
			srcMACstring = getDriver().byteArrayToString(srcMAC).substring(0, 17);
			etherTypeString = getDriver().byteArrayToString(etherType).substring(0, 5);

			// any byte array with length > 16 must be converted by byte since
			//   "byteArrayToString()" adds an interpretation after each group of 16 bytes
			ethPayloadString = "";
			for (int i=0; i<ethPayload.length; i++) {
				ethPayloadString += getDriver().byteToHex(ethPayload[i])+" ";
			}
		}
		return outputS;
	}

	public void printEthRawParse () {
		if (dstMAC==null) {
			System.out.println("Ethernet packet not parsed.");
		}
		else {
			System.out.println("dstMAC: "+dstMACstring);
			System.out.println("srcMAC: "+srcMACstring);
			System.out.println("etherTyp: "+etherTypeString);
			System.out.println("ethPayload (length="+ethPayloadLength+"):\n"+ethPayloadString);
			System.out.println("");
		}
	}

	public String EthPrettyParse (int packetNum) {
		String parseS = "";

		parseS += "\n*****************************************"
				+ "****************************"+
				"\n                              Packet "+(packetNum+1)+
				"\n**************************************************"
				+ "*******************\n";
		parseS += "\nEthernet\n"
				+ "==================================\n";
		if (dstMAC==null) {
			parseS += "Ethernet packet not parsed.\n";
		}
		else {
			parseS += "dstMAC: "+dstMACstring.replaceAll("\\s", ":")+"\n";
			parseS += "srcMAC: "+srcMACstring.replaceAll("\\s", ":")+"\n";

			if (etherTypeString.equals("08 00")) {
				parseS += "etherType: IP (0x0800)\n";
			}
			else if (etherTypeString.equals("08 06")) {
				parseS += "etherType: ARP (0x0806)\n";
			}
			else {
				parseS += "etherType: 0x"+etherTypeString.replaceAll("\\s", "")+"\n";
			}

			parseS += "ethPayload length: "+ethPayloadLength+"\n";
			
			parseS += "ethPayload:\n"+
					getDriver().byteArrayToString(ethPayload);
		}
		return parseS;
	}

	public String getEtherType() {
		if (etherType==null) {
			return "Unparsed";
		}
		else if (etherTypeString.equals("08 00")) {
			return "IP";
		}
		else if (etherTypeString.equals("08 06")) {
			return "ARP";
		}
		else {
			return "Unknown";
		}
	}

	public byte[] getDstMAC() {
		return dstMAC;
	}

	public void setDstMAC(byte[] dstMAC) {
		this.dstMAC = dstMAC;
	}

	public byte[] getSrcMAC() {
		return srcMAC;
	}

	public void setSrcMAC(byte[] srcMAC) {
		this.srcMAC = srcMAC;
	}

	public byte[] getEthPayload() {
		return ethPayload;
	}

	public void setEthPayload(byte[] ethPayload) {
		this.ethPayload = ethPayload;
	}

	public byte[] getCRCchecksum() {
		return CRCchecksum;
	}

	public void setCRCchecksum(byte[] cRCchecksum) {
		CRCchecksum = cRCchecksum;
	}

	public String getDstMACstring() {
		return dstMACstring;
	}

	public void setDstMACstring(String dstMACstring) {
		this.dstMACstring = dstMACstring;
	}

	public String getSrcMACstring() {
		return srcMACstring;
	}

	public void setSrcMACstring(String srcMACstring) {
		this.srcMACstring = srcMACstring;
	}

	public String getEtherTypeString() {
		return etherTypeString;
	}

	public void setEtherTypeString(String etherTypeString) {
		this.etherTypeString = etherTypeString;
	}

	public String getEthPayloadString() {
		return ethPayloadString;
	}

	public void setEthPayloadString(String ethPayloadString) {
		this.ethPayloadString = ethPayloadString;
	}

	public int getEthPayloadLength() {
		return ethPayloadLength;
	}

	public void setEthPayloadLength(int ethPayloadLength) {
		this.ethPayloadLength = ethPayloadLength;
	}

	public void setEtherType(byte[] etherType) {
		this.etherType = etherType;
	}
}
