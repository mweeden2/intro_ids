/*
 * UDP Packet
 * 2/3/16 - 3/15/16
 * 
 * by Matt Weeden
 * 
 * CS 7473 Network Security
 * Dr. Mauricio Papa
 * 
 */

import java.util.Arrays;

public class UDPPacket extends IPPacket {

	private byte[] srcPort;
	private byte[] dstPort;
	private byte[] UDPtotalLength;
	private byte[] UDPchecksum;
	private byte[] UDPpayload;

	private String srcPortString;
	private String dstPortString;
	private String UDPtotalLengthString;
	private String UDPchecksumString;
	private String UDPpayloadString;

	private int sPortI;
	private int dPortI;

	private int UDPpayloadLengthI;
	private int UDPtotalLengthI;

	public UDPPacket (byte[] bs) {
		super(bs);
	}

	public String parseUDP () {
		String outputS = "";

		outputS += super.parseIP();

		if (getIPpayload().length<8) {
			//outputS += "\nThis packet's UDP header isn't long enough.\n\n";
		}
		else {
			srcPort = Arrays.copyOfRange(getIPpayload(), 0, 2);
			dstPort = Arrays.copyOfRange(getIPpayload(), 2, 4);
			UDPtotalLength = Arrays.copyOfRange(getIPpayload(), 4, 6);
			UDPchecksum = Arrays.copyOfRange(getIPpayload(), 6, 8);

			srcPortString = getDriver().byteArrayToString(srcPort).substring(0, 5);
			dstPortString = getDriver().byteArrayToString(dstPort).substring(0, 5);
			UDPtotalLengthString = getDriver().byteArrayToString(UDPtotalLength).substring(0, 5);
			UDPchecksumString = getDriver().byteArrayToString(UDPchecksum).substring(0, 5);

			sPortI = Integer.parseInt(srcPortString.replaceAll("\\s", ""), 16);
			dPortI = Integer.parseInt(dstPortString.replaceAll("\\s", ""), 16);
			
			//UDPtotalLengthI = Integer.parseInt(UDPtotalLengthString.replaceAll
					//("\\s", ""), 16);

			UDPtotalLengthI = getIPpayloadLengthI();
			
			// get payload based on IPPayload length
			UDPpayloadLengthI = getIPpayloadLengthI() - 8;
			if (UDPpayloadLengthI>0) {
				UDPpayload = Arrays.copyOfRange(getIPpayload(), 8, UDPtotalLengthI);
				UDPpayloadString = "";
				for (int i=0; i<UDPpayload.length; i++) {
					UDPpayloadString += getDriver().byteToHex(UDPpayload[i])+" ";
				}
			}
		}
		return outputS;
	}

	public void printUDPrawParse () {
		if (srcPort==null) {
			System.out.println("UDP packet not parsed.");
		}
		else {
			System.out.println("srcPort: "+srcPortString);
			System.out.println("dstPort: "+dstPortString);
			System.out.println("UDPtotalLength: "+UDPtotalLengthString);
			System.out.println("UDPchecksum: "+UDPchecksumString);
			if (UDPpayloadLengthI>0) {
				System.out.println("IPpayload (length="+UDPpayloadLengthI+"):\n"+
						UDPpayloadString);
			}
			else {
				System.out.println("There is no UDP payload.");
			}
		}
	}

	public String UDPprettyParse () {
		String parseS = "";
		parseS += "\nUDP\n"
				+ "==================================\n";
		if (srcPort==null) {
			parseS += "UDP packet not parsed.\n";
		}
		else {
			parseS += "srcPort: "+sPortI+"\n";
			parseS += "dstPort: "+dPortI+"\n";
			parseS += "UDPtotalLength: "+Integer.parseInt
					(UDPtotalLengthString.replaceAll("\\s", ""), 16)+"\n";
			parseS += "UDPchecksum: 0x"+UDPchecksumString.replaceAll("\\s", "")+"\n";
			parseS += "UDPpayload length: "+UDPpayloadLengthI+"\n";
			if (UDPpayloadLengthI>0 && getIPpayloadLengthI() > 8) {
				parseS += "UDPpayload:\n"+
						getDriver().byteArrayToString(UDPpayload)+"\n";
			}
			else {
				parseS += "There is no UDP payload.\n";
			}
		}
		return parseS;
	}

	public byte[] getSrcPort() {
		return srcPort;
	}

	public void setSrcPort(byte[] srcPort) {
		this.srcPort = srcPort;
	}

	public byte[] getDstPort() {
		return dstPort;
	}

	public void setDstPort(byte[] dstPort) {
		this.dstPort = dstPort;
	}

	public byte[] getUDPtotalLength() {
		return UDPtotalLength;
	}

	public void setUDPtotalLength(byte[] uDPtotalLength) {
		UDPtotalLength = uDPtotalLength;
	}

	public byte[] getUDPchecksum() {
		return UDPchecksum;
	}

	public void setUDPchecksum(byte[] uDPchecksum) {
		UDPchecksum = uDPchecksum;
	}

	public byte[] getUDPpayload() {
		return UDPpayload;
	}

	public void setUDPpayload(byte[] uDPpayload) {
		UDPpayload = uDPpayload;
	}

	public String getSrcPortString() {
		return srcPortString;
	}

	public void setSrcPortString(String srcPortString) {
		this.srcPortString = srcPortString;
	}

	public String getDstPortString() {
		return dstPortString;
	}

	public void setDstPortString(String dstPortString) {
		this.dstPortString = dstPortString;
	}

	public String getUDPtotalLengthString() {
		return UDPtotalLengthString;
	}

	public void setUDPtotalLengthString(String uDPtotalLengthString) {
		UDPtotalLengthString = uDPtotalLengthString;
	}

	public String getUDPchecksumString() {
		return UDPchecksumString;
	}

	public void setUDPchecksumString(String uDPchecksumString) {
		UDPchecksumString = uDPchecksumString;
	}

	public String getUDPpayloadString() {
		return UDPpayloadString;
	}

	public void setUDPpayloadString(String uDPpayloadString) {
		UDPpayloadString = uDPpayloadString;
	}

	public int getSPortI() {
		return sPortI;
	}

	public void setSPortI(int sPortI) {
		this.sPortI = sPortI;
	}

	public int getDPortI() {
		return dPortI;
	}

	public void setDPortI(int dPortI) {
		this.dPortI = dPortI;
	}

	public int getUDPpayloadLengthI() {
		return UDPpayloadLengthI;
	}

	public void setUDPpayloadLengthI(int uDPpayloadLengthI) {
		UDPpayloadLengthI = uDPpayloadLengthI;
	}

	public int getUDPtotalLengthI() {
		return UDPtotalLengthI;
	}

	public void setUDPtotalLengthI(int uDPtotalLengthI) {
		UDPtotalLengthI = uDPtotalLengthI;
	}
}
