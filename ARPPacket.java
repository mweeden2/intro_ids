/*
 * ARP Packet
 * 2/3/16 - 3/15/16
 * 
 * by Matt Weeden
 * 
 * CS 7473 Network Security
 * Dr. Mauricio Papa
 * 
 */

import java.util.Arrays;

public class ARPPacket extends EthernetPacket {

	private byte[] hardwareType;
	private byte[] protocolType;
	private byte[] hardwareAddLength;
	private byte[] protocolAddLength;
	private byte[] operation;
	private byte[] senderHardwareAdd;
	private byte[] senderProtocolAdd;
	private byte[] targetHardwareAdd;
	private byte[] targetProtocolAdd;

	private String hardwareTypeString;
	private String protocolTypeString;
	private String hardwareAddLengthString;
	private String protocolAddLengthString;
	private String operationString;
	private String senderHardwareAddString;
	private String senderProtocolAddString;
	private String targetHardwareAddString;
	private String targetProtocolAddString;
	
	private String senderProtocolAddDottedString;
	private String targetProtocolAddDottedString;

	public ARPPacket (byte[] bs) {
		super(bs);
	}

	// assume hardware is always Ethernet
	// assume protocol is always IP
	public String parseARP () {
		String outputS = "";

		outputS += super.parseEthernet();

		if (getEthPayload().length<28) {
			//outputS += "\nThis packet's ARP header isn't long enough.\n\n";
		}
		else {
			hardwareType = Arrays.copyOfRange(getEthPayload(), 0, 2);
			protocolType = Arrays.copyOfRange(getEthPayload(), 2, 4);
			hardwareAddLength = new byte[1];
			hardwareAddLength[0] = getEthPayload()[4];
			protocolAddLength = new byte[1];
			protocolAddLength[0] = getEthPayload()[5];
			operation = Arrays.copyOfRange(getEthPayload(), 6, 8);
			senderHardwareAdd = Arrays.copyOfRange(getEthPayload(), 8, 14);
			senderProtocolAdd = Arrays.copyOfRange(getEthPayload(), 14, 18);
			targetHardwareAdd = Arrays.copyOfRange(getEthPayload(), 18, 24);
			targetProtocolAdd = Arrays.copyOfRange(getEthPayload(), 24, 28);

			hardwareTypeString = getDriver().byteArrayToString(hardwareType).substring(0, 5);
			protocolTypeString = getDriver().byteArrayToString(protocolType).substring(0, 5);
			hardwareAddLengthString = getDriver().byteArrayToString
					(hardwareAddLength).substring(0, 2);
			protocolAddLengthString = getDriver().byteArrayToString
					(protocolAddLength).substring(0, 2);
			operationString = getDriver().byteArrayToString(operation).substring(0, 5);
			senderHardwareAddString = getDriver().byteArrayToString
					(senderHardwareAdd).substring(0, 17);
			senderProtocolAddString = getDriver().byteArrayToString
					(senderProtocolAdd).substring(0, 11);
			targetHardwareAddString = getDriver().byteArrayToString
					(targetHardwareAdd).substring(0, 17);
			targetProtocolAddString = getDriver().byteArrayToString
					(targetProtocolAdd).substring(0, 11);

			// convert protocol (IP) addresses to dot notation
			senderProtocolAddDottedString = "";
			for (int i=0; i<4; i++) {
				senderProtocolAddDottedString += Integer.parseInt(senderProtocolAddString.substring
						(i*3, i*3+2), 16);
				if (i<3) {
					senderProtocolAddDottedString += ".";
				}
			}
			targetProtocolAddDottedString = "";
			for (int i=0; i<4; i++) {
				targetProtocolAddDottedString += Integer.parseInt(targetProtocolAddString.substring
						(i*3, i*3+2), 16);
				if (i<3) {
					targetProtocolAddDottedString += ".";
				}
			}			
		}
		return outputS;
	}

	public void printARPrawParse () {
		if (hardwareType==null) {
			System.out.println("ARP packet not parsed.");
		}
		else {
			System.out.println("hardwareType: "+hardwareTypeString);
			System.out.println("protocolType: "+protocolTypeString);
			System.out.println("hardwareAddLength: "+hardwareAddLengthString);
			System.out.println("protocolAddLength: "+protocolAddLengthString);
			System.out.println("operation: "+operationString);
			System.out.println("senderHardwareAdd: "+senderHardwareAddString);
			System.out.println("senderProtocolAdd: "+senderProtocolAddString);
			System.out.println("targetHardwareAdd: "+targetHardwareAddString);
			System.out.println("targetProtocolAdd: "+targetProtocolAddString);
		}
	}

	public String ARPprettyParse () {
		String parseS = "";

		parseS += "ARP\n"
				+ "==================================\n";
		if (hardwareType==null) {
			parseS += "ARP packet not parsed.\n";
		}
		else {
			if (hardwareTypeString.equals("00 01")) {
				parseS += "hardwareType: Ethernet (1)\n";
			}
			else {
				parseS += "hardwareType: "+Integer.parseInt
						(hardwareTypeString.replaceAll("\\s", ""), 16)+"\n";
			}
			if (protocolTypeString.equals("08 00")) {
				parseS += "protocolType: IP (0x0800)\n";
			}
			else {
				parseS += "protocolType: 0x"+protocolTypeString.replaceAll
						("\\s", "")+"\n";
			}
			parseS += "hardwareAddLength: "+Integer.parseInt
					(hardwareAddLengthString, 16)+"\n";
			parseS += "protocolAddLength: "+Integer.parseInt
					(protocolAddLengthString, 16)+"\n";
			if (operationString.equals("00 01")) {
				parseS += "operation: request (1)\n";
			}
			else if (operationString.equals("00 02")) {
				parseS += "operation: reply (2)\n";
			}
			else {
				parseS += "operation: "+Integer.parseInt
						(operationString.replaceAll("\\s", ""), 16)+"\n";
			}
			parseS += "senderHardwareAdd: "+
					senderHardwareAddString.replaceAll("\\s", ":")+"\n";

			// print protocol (IP) addresses in dot notation
			parseS += "senderProtocolAdd: "+senderProtocolAddDottedString;

			parseS += "\ntargetHardwareAdd: "+
					targetHardwareAddString.replaceAll("\\s", ":")+"\n";

			parseS += "targetProtocolAdd: "+targetProtocolAddDottedString+"\n";
		}
		return parseS;
	}

	public byte[] getHardwareType() {
		return hardwareType;
	}

	public void setHardwareType(byte[] hardwareType) {
		this.hardwareType = hardwareType;
	}

	public byte[] getProtocolType() {
		return protocolType;
	}

	public void setProtocolType(byte[] protocolType) {
		this.protocolType = protocolType;
	}

	public byte[] getHardwareAddLength() {
		return hardwareAddLength;
	}

	public void setHardwareAddLength(byte[] hardwareAddLength) {
		this.hardwareAddLength = hardwareAddLength;
	}

	public byte[] getProtocolAddLength() {
		return protocolAddLength;
	}

	public void setProtocolAddLength(byte[] protocolAddLength) {
		this.protocolAddLength = protocolAddLength;
	}

	public byte[] getOperation() {
		return operation;
	}

	public void setOperation(byte[] operation) {
		this.operation = operation;
	}

	public byte[] getSenderHardwareAdd() {
		return senderHardwareAdd;
	}

	public void setSenderHardwareAdd(byte[] senderHardwareAdd) {
		this.senderHardwareAdd = senderHardwareAdd;
	}

	public byte[] getSenderProtocolAdd() {
		return senderProtocolAdd;
	}

	public void setSenderProtocolAdd(byte[] senderProtocolAdd) {
		this.senderProtocolAdd = senderProtocolAdd;
	}

	public byte[] getTargetHardwareAdd() {
		return targetHardwareAdd;
	}

	public void setTargetHardwareAdd(byte[] targetHardwareAdd) {
		this.targetHardwareAdd = targetHardwareAdd;
	}

	public byte[] getTargetProtocolAdd() {
		return targetProtocolAdd;
	}

	public void setTargetProtocolAdd(byte[] targetProtocolAdd) {
		this.targetProtocolAdd = targetProtocolAdd;
	}

	public String getHardwareTypeString() {
		return hardwareTypeString;
	}

	public void setHardwareTypeString(String hardwareTypeString) {
		this.hardwareTypeString = hardwareTypeString;
	}

	public String getProtocolTypeString() {
		return protocolTypeString;
	}

	public void setProtocolTypeString(String protocolTypeString) {
		this.protocolTypeString = protocolTypeString;
	}

	public String getHardwareAddLengthString() {
		return hardwareAddLengthString;
	}

	public void setHardwareAddLengthString(String hardwareAddLengthString) {
		this.hardwareAddLengthString = hardwareAddLengthString;
	}

	public String getProtocolAddLengthString() {
		return protocolAddLengthString;
	}

	public void setProtocolAddLengthString(String protocolAddLengthString) {
		this.protocolAddLengthString = protocolAddLengthString;
	}

	public String getOperationString() {
		return operationString;
	}

	public void setOperationString(String operationString) {
		this.operationString = operationString;
	}

	public String getSenderHardwareAddString() {
		return senderHardwareAddString;
	}

	public void setSenderHardwareAddString(String senderHardwareAddString) {
		this.senderHardwareAddString = senderHardwareAddString;
	}

	public String getSenderProtocolAddString() {
		return senderProtocolAddString;
	}

	public void setSenderProtocolAddString(String senderProtocolAddString) {
		this.senderProtocolAddString = senderProtocolAddString;
	}

	public String getTargetHardwareAddString() {
		return targetHardwareAddString;
	}

	public void setTargetHardwareAddString(String targetHardwareAddString) {
		this.targetHardwareAddString = targetHardwareAddString;
	}

	public String getTargetProtocolAddString() {
		return targetProtocolAddString;
	}

	public void setTargetProtocolAddString(String targetProtocolAddString) {
		this.targetProtocolAddString = targetProtocolAddString;
	}

	public String getSenderProtocolAddDottedString() {
		return senderProtocolAddDottedString;
	}

	public void setSenderProtocolAddDottedString(String senderProtocolAddDottedString) {
		this.senderProtocolAddDottedString = senderProtocolAddDottedString;
	}

	public String getTargetProtocolAddDottedString() {
		return targetProtocolAddDottedString;
	}

	public void setTargetProtocolAddDottedString(String targetProtocolAddDottedString) {
		this.targetProtocolAddDottedString = targetProtocolAddDottedString;
	}
}
