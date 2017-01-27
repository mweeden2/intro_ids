/*
 * TCP Packet
 * 2/3/16 - 3/15/16
 * 
 * by Matt Weeden
 * 
 * CS 7473 Network Security
 * Dr. Mauricio Papa
 * 
 */

import java.util.Arrays;

public class TCPPacket extends IPPacket {

	private byte[] srcPort;
	private byte[] dstPort;
	private byte[] sequenceNum;
	private byte[] ACKnum;
	private byte[] dataOffset;  // num of 32-bit words in the TCP header
	// Assume 6 bits of 0's for Reserved field
	private boolean URG;
	private boolean ACK;
	private boolean PSH;
	private boolean RST;
	private boolean SYN;
	private boolean FIN;
	private byte[] window;
	private byte[] TCPchecksum;
	private byte[] urgentPointer;
	private byte[] TCPoptions;
	private byte[] TCPpayload;

	private String srcPortString;
	private String dstPortString;
	private String sequenceNumString;
	private String ACKnumString;
	private String dataOffsetString;
	private String windowString;
	private String TCPchecksumString;
	private String urgentPointerString;
	private String TCPoptionsString;
	private String TCPpayloadString;
	
	private int sPortI;
	private int dPortI;
	
	private int dataOffsetI;
	private int TCPoptionsLengthI;
	private int TCPpayloadLengthI;
	
	public TCPPacket (byte[] bs) {
		super(bs);
	}

	public String parseTCP () {
		String outputS = "";
		
		outputS += super.parseIP();

		if (getIPpayloadLengthI()<20) {
			//outputS += "\nThis packet's TCP header isn't long enough.";
		}
		else {
			srcPort = Arrays.copyOfRange(getIPpayload(), 0, 2);
			dstPort = Arrays.copyOfRange(getIPpayload(), 2, 4);
			sequenceNum = Arrays.copyOfRange(getIPpayload(), 4, 8);
			ACKnum = Arrays.copyOfRange(getIPpayload(), 8, 12);
			dataOffset = new byte[1];
			dataOffset[0] = (byte) ((getIPpayload()[12] & 0x70) >>> 4);
			// use SimplePacketDriver.byteToHex to avoid signed byte errors
			URG = isSet(getDriver().byteToHex(getIPpayload()[13]), 5);
			ACK = isSet(getDriver().byteToHex(getIPpayload()[13]), 4);
			PSH = isSet(getDriver().byteToHex(getIPpayload()[13]), 3);
			RST = isSet(getDriver().byteToHex(getIPpayload()[13]), 2);
			SYN = isSet(getDriver().byteToHex(getIPpayload()[13]), 1);
			FIN = isSet(getDriver().byteToHex(getIPpayload()[13]), 0);
			window = Arrays.copyOfRange(getIPpayload(), 14, 16);
			TCPchecksum = Arrays.copyOfRange(getIPpayload(), 16, 18);
			urgentPointer = Arrays.copyOfRange(getIPpayload(), 18, 20); 

			srcPortString = getDriver().byteArrayToString(srcPort).substring(0, 5);
			dstPortString = getDriver().byteArrayToString(dstPort).substring(0, 5);
			sequenceNumString = 
					getDriver().byteArrayToString(sequenceNum).substring(0, 11);
			ACKnumString = getDriver().byteArrayToString(ACKnum).substring(0, 11);
			dataOffsetString = getDriver().byteArrayToString(dataOffset).substring(0, 2);
			windowString = getDriver().byteArrayToString(window).substring(0, 5);
			TCPchecksumString = 
					getDriver().byteArrayToString(TCPchecksum).substring(0, 5);
			urgentPointerString = 
					getDriver().byteArrayToString(urgentPointer).substring(0, 5);

			sPortI = Integer.parseInt(srcPortString.replaceAll("\\s", ""), 16);
			dPortI = Integer.parseInt(dstPortString.replaceAll("\\s", ""), 16);
			
			// Data Offset is the number of 32-bit words in the TCP header
			dataOffsetI = Integer.parseInt(dataOffsetString, 16);

			// get options based on Data Offset
			if (dataOffsetI>5) {
				TCPoptions= Arrays.copyOfRange(getIPpayload(), 20, (dataOffsetI*4));
				TCPoptionsString = "";
				for (int i=0; i<TCPoptions.length; i++) {
					TCPoptionsString += getDriver().byteToHex(TCPoptions[i])+" ";
				}
			}
			
			TCPoptionsLengthI = (dataOffsetI-5)*4;
			TCPpayloadLengthI = getIPpayloadLengthI()-(dataOffsetI*4);
			
			// get payload based on IP payload length and Data Offset
			if (TCPpayloadLengthI>0) {
				TCPpayload = Arrays.copyOfRange(getIPpayload(), (dataOffsetI*4), 
						getIPpayloadLengthI());
				TCPpayloadString = "";
				for (int i=0; i<TCPpayload.length; i++) {
					TCPpayloadString += getDriver().byteToHex(TCPpayload[i])+" ";
				}
			}
		}
		return outputS;
	}

	public void printTCPrawParse () {
		if (srcPort==null) {
			System.out.println("TCP packet not parsed.");
		}
		else {
			System.out.println("srcPort: "+srcPortString);
			System.out.println("dstPort: "+dstPortString);
			System.out.println("sequenceNum: "+sequenceNumString);
			System.out.println("ACKnum: "+ACKnumString);
			System.out.println("dataOffset: "+dataOffsetString);
			System.out.println("URG: "+URG);
			System.out.println("ACK: "+ACK);
			System.out.println("PSH: "+PSH);
			System.out.println("RST: "+RST);
			System.out.println("SYN: "+SYN);
			System.out.println("FIN: "+FIN);
			System.out.println("window: "+windowString);
			System.out.println("TCPchecksum: "+TCPchecksumString);
			System.out.println("urgentPointer: "+urgentPointerString);
			
			if (dataOffsetI>5) {
				System.out.println("options: "+TCPoptionsString);
			}
			else {
				System.out.println("There are no TCP options.");
			}
			if (TCPpayloadLengthI>0) {
				System.out.println("TCPpayload (length="+TCPpayloadLengthI+"):\n"+
						TCPpayloadString);
			}
			else {
				System.out.println("There is no TCP payload.");
			}
		}
	}

	public String TCPprettyParse() {
		String parseS = "";
		parseS += "\nTCP\n"
				+ "==================================\n";
		if (srcPort==null) {
			parseS += "TCP packet not parsed.\n";
		}
		else {
			parseS += "srcPort: "+sPortI+"\n";
			parseS += "dstPort: "+dPortI+"\n";
			parseS += "sequenceNum: "+
					Long.parseLong(sequenceNumString.replaceAll("\\s", ""), 16)+"\n";
			parseS += "ACKnum: "+
					Long.parseLong(ACKnumString.replaceAll("\\s", ""), 16)+"\n";
			parseS += "dataOffset: "+Integer.parseInt(dataOffsetString, 16)+"\n";
			parseS += "URG: "+URG+"\n";
			parseS += "ACK: "+ACK+"\n";
			parseS += "PSH: "+PSH+"\n";
			parseS += "RST: "+RST+"\n";
			parseS += "SYN: "+SYN+"\n";
			parseS += "FIN: "+FIN+"\n";
			parseS += "window: "+
					Integer.parseInt(windowString.replaceAll("\\s", ""), 16)+"\n";
			parseS += "TCPchecksum: 0x"+TCPchecksumString.replaceAll("\\s", "")+"\n";
			parseS += "urgentPointer: "+Integer.parseInt
					(urgentPointerString.replaceAll("\\s", ""), 16)+"\n";
			
			if (dataOffsetI>5) {
				parseS += "options (length="+TCPoptionsLengthI+"):\n"+
						getDriver().byteArrayToString(TCPoptions)+"\n";
			}
			else {
				parseS += "There are no TCP options.\n";
			}
			
			parseS += "TCPpayload length: "+TCPpayloadLengthI+"\n";
			
			if (TCPpayloadLengthI>0) {
				parseS += "TCPpayload:\n"+
						getDriver().byteArrayToString(TCPpayload);
			}
			else {
				parseS += "There is no TCP payload.\n";
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

	public byte[] getSequenceNum() {
		return sequenceNum;
	}

	public void setSequenceNum(byte[] sequenceNum) {
		this.sequenceNum = sequenceNum;
	}

	public byte[] getACKnum() {
		return ACKnum;
	}

	public void setACKnum(byte[] aCKnum) {
		ACKnum = aCKnum;
	}

	public byte[] getDataOffset() {
		return dataOffset;
	}

	public void setDataOffset(byte[] dataOffset) {
		this.dataOffset = dataOffset;
	}

	public boolean isURG() {
		return URG;
	}

	public void setURG(boolean uRG) {
		URG = uRG;
	}

	public boolean isACK() {
		return ACK;
	}

	public void setACK(boolean aCK) {
		ACK = aCK;
	}

	public boolean isPSH() {
		return PSH;
	}

	public void setPSH(boolean pSH) {
		PSH = pSH;
	}

	public boolean isRST() {
		return RST;
	}

	public void setRST(boolean rST) {
		RST = rST;
	}

	public boolean isSYN() {
		return SYN;
	}

	public void setSYN(boolean sYN) {
		SYN = sYN;
	}

	public boolean isFIN() {
		return FIN;
	}

	public void setFIN(boolean fIN) {
		FIN = fIN;
	}

	public byte[] getWindow() {
		return window;
	}

	public void setWindow(byte[] window) {
		this.window = window;
	}

	public byte[] getTCPchecksum() {
		return TCPchecksum;
	}

	public void setTCPchecksum(byte[] tCPchecksum) {
		TCPchecksum = tCPchecksum;
	}

	public byte[] getUrgentPointer() {
		return urgentPointer;
	}

	public void setUrgentPointer(byte[] urgentPointer) {
		this.urgentPointer = urgentPointer;
	}

	public byte[] getTCPoptions() {
		return TCPoptions;
	}

	public void setTCPoptions(byte[] tCPoptions) {
		TCPoptions = tCPoptions;
	}

	public byte[] getTCPpayload() {
		return TCPpayload;
	}

	public void setTCPpayload(byte[] tCPpayload) {
		TCPpayload = tCPpayload;
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

	public String getSequenceNumString() {
		return sequenceNumString;
	}

	public void setSequenceNumString(String sequenceNumString) {
		this.sequenceNumString = sequenceNumString;
	}

	public String getACKnumString() {
		return ACKnumString;
	}

	public void setACKnumString(String aCKnumString) {
		ACKnumString = aCKnumString;
	}

	public String getDataOffsetString() {
		return dataOffsetString;
	}

	public void setDataOffsetString(String dataOffsetString) {
		this.dataOffsetString = dataOffsetString;
	}

	public String getWindowString() {
		return windowString;
	}

	public void setWindowString(String windowString) {
		this.windowString = windowString;
	}

	public String getTCPchecksumString() {
		return TCPchecksumString;
	}

	public void setTCPchecksumString(String tCPchecksumString) {
		TCPchecksumString = tCPchecksumString;
	}

	public String getUrgentPointerString() {
		return urgentPointerString;
	}

	public void setUrgentPointerString(String urgentPointerString) {
		this.urgentPointerString = urgentPointerString;
	}

	public String getTCPoptionsString() {
		return TCPoptionsString;
	}

	public void setTCPoptionsString(String tCPoptionsString) {
		TCPoptionsString = tCPoptionsString;
	}

	public String getTCPpayloadString() {
		return TCPpayloadString;
	}

	public void setTCPpayloadString(String tCPpayloadString) {
		TCPpayloadString = tCPpayloadString;
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

	public int getDataOffsetI() {
		return dataOffsetI;
	}

	public void setDataOffsetI(int dataOffsetI) {
		this.dataOffsetI = dataOffsetI;
	}

	public int getTCPoptionsLengthI() {
		return TCPoptionsLengthI;
	}

	public void setTCPoptionsLengthI(int tCPoptionsLengthI) {
		TCPoptionsLengthI = tCPoptionsLengthI;
	}

	public int getTCPpayloadLengthI() {
		return TCPpayloadLengthI;
	}

	public void setTCPpayloadLengthI(int tCPpayloadLengthI) {
		TCPpayloadLengthI = tCPpayloadLengthI;
	}
}
