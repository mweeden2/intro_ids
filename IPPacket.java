/*
 * IP Packet
 * 2/3/16 - 3/15/16
 * 
 * by Matt Weeden
 * 
 * CS 7473 Network Security
 * Dr. Mauricio Papa
 * 
 */

import java.util.Arrays;

public class IPPacket extends EthernetPacket{

	private byte[] version;
	private byte[] IHL;
	private byte[] TOS;
	private byte[] IPtotalLength;
	private byte[] identification;
	private boolean dontFragment;
	private boolean moreFragments;
	private boolean reservedBit;
	private byte[] fragmentOffset;
	private byte[] TTL;
	private byte[] protocol;
	private byte[] headerChecksum;
	private byte[] srcIP;
	private byte[] dstIP;
	private byte[] IPoptions;
	private byte[] IPpayload;

	private String versionString;
	private String IHLstring;
	private String TOSstring;
	private String IPtotalLengthString;
	private String identificationString;
	private String fragmentOffsetString;
	private String TTLstring;
	private String protocolString;
	private String headerChecksumString;
	private String srcIPstring;
	private String dstIPstring;
	private String IPoptionsString;
	private String IPpayloadString;

	private String srcIPdottedString;
	private String dstIPdottedString;

	private int identificationI;
	private int fragmentOffsetI;

	// only IHL is in 4-byte units
	private int IHLi;
	private int IPtotalLengthI;
	private int IPoptionsLengthI;
	private int IPpayloadLengthI;

	public IPPacket(byte[] bs) {
		super(bs);
	}

	public String parseIP() {
		String outputS = "";

		outputS += super.parseEthernet();

		if (getEthPayload().length<20) {
			//outputS += "\nThis packet's IP header isn't long enough.\n\n";
		}
		else {
			version = new byte[1];
			version[0] = (byte) (((getEthPayload()[0] & 0xF0)) >>> 4);
			IHL = new byte[1];
			IHL[0] = (byte) (getEthPayload()[0] & 0x0F);
			TOS = new byte[1];
			TOS[0] = getEthPayload()[1];
			IPtotalLength = Arrays.copyOfRange(getEthPayload(), 2, 4);
			identification = Arrays.copyOfRange(getEthPayload(), 4, 6);
			// use SimplePacketgetDriver().byteToHex to avoid signed byte errors
			dontFragment = isSet(getDriver().byteToHex(getEthPayload()[6]), 6);
			moreFragments = isSet(getDriver().byteToHex(getEthPayload()[6]), 5);
			reservedBit = isSet(getDriver().byteToHex(getEthPayload()[6]), 7);
			fragmentOffset = new byte[2];
			fragmentOffset[0] = (byte) (getEthPayload()[6] & 0x1F);
			fragmentOffset[1] = getEthPayload()[7];
			TTL = new byte[1];
			TTL[0] = getEthPayload()[8];
			protocol = new byte[1];
			protocol[0] = getEthPayload()[9];
			headerChecksum = Arrays.copyOfRange(getEthPayload(), 10, 12);
			srcIP = Arrays.copyOfRange(getEthPayload(), 12, 16);
			dstIP = Arrays.copyOfRange(getEthPayload(), 16, 20);

			versionString = getDriver().byteArrayToString(version).substring(0, 2);
			IHLstring = getDriver().byteArrayToString(IHL).substring(0, 2);
			TOSstring = getDriver().byteArrayToString(TOS).substring(0, 2);
			IPtotalLengthString = 
					getDriver().byteArrayToString(IPtotalLength).substring(0, 5);
			identificationString = 
					getDriver().byteArrayToString(identification).substring(0, 5);
			fragmentOffsetString = 
					getDriver().byteArrayToString(fragmentOffset).substring(0, 5);
			TTLstring = getDriver().byteArrayToString(TTL).substring(0, 2);
			protocolString = getDriver().byteArrayToString(protocol).substring(0, 2);
			headerChecksumString = 
					getDriver().byteArrayToString(headerChecksum).substring(0, 5);
			srcIPstring = getDriver().byteArrayToString(srcIP).substring(0, 11);
			dstIPstring = getDriver().byteArrayToString(dstIP).substring(0, 11);

			identificationI = 
					Integer.parseInt(identificationString.replaceAll("\\s", ""), 16);
			fragmentOffsetI = Integer.parseInt
					(fragmentOffsetString.replaceAll("\\s", ""), 16);

			// put IP addresses in dotted notation
			srcIPdottedString = "";
			for (int i=0; i<4; i++) {
				srcIPdottedString += 
						Integer.parseInt(srcIPstring.substring(i*3, i*3+2), 16);
				if (i<3) {
					srcIPdottedString += ".";
				}
			}
			dstIPdottedString = "";
			for (int i=0; i<4; i++) {
				dstIPdottedString += 
						Integer.parseInt(dstIPstring.substring(i*3, i*3+2), 16);
				if (i<3) {
					dstIPdottedString += ".";
				}
			}

			// IHL is in 4-byte units
			IHLi = Integer.parseInt(IHLstring, 16);
			IPtotalLengthI = 
					Integer.parseInt(IPtotalLengthString.replaceAll("\\s",""), 16);
			IPoptionsLengthI = IHLi-5;
			IPpayloadLengthI = IPtotalLengthI-IHLi;

			// get options based on IHL
			if (IHLi>5) {
				IPoptions = Arrays.copyOfRange(getEthPayload(), 20, (IHLi*4));
				IPoptionsString = "";
				for (int i=0; i<IPoptions.length; i++) {
					IPoptionsString += getDriver().byteToHex(IPoptions[i])+" ";
				}
			}
			// get payload based on IHL and Total Length
			IPpayloadLengthI = IPtotalLengthI-(IHLi*4);
			if (IPpayloadLengthI>0) {
				IPpayload = Arrays.copyOfRange(getEthPayload(), (IHLi*4), IPtotalLengthI);
				IPpayloadString = "";
				for (int i=0; i<IPpayload.length; i++) {
					IPpayloadString += getDriver().byteToHex(IPpayload[i])+" ";
				}
			}
		}
		return outputS;
	}

	public boolean checkChecksum() {
		boolean good = false;

		int sum = 0;

		// loop through 16-bit values of the header
		for (int i=0; i<(IHLi*2); i++) {
			sum += Byte.toUnsignedInt(getEthPayload()[2*i])*256 + 
					Byte.toUnsignedInt(getEthPayload()[2*i+1]);
		}
		// move carry bits to least significant bit
		while (sum>65536) {
			sum = sum - 65536 + 1;
		}
		// check if correct
		if (sum == 65535) {
			good = true;
		}

		return good;
	}

	public void printIPrawParse () {

		if (version==null) {
			System.out.println("IP packet not parsed.");
		}
		else {
			System.out.println("version: "+versionString);
			System.out.println("IHL: "+IHLstring);
			System.out.println("TOS: "+TOSstring);
			System.out.println("IPtotalLength: "+IPtotalLengthString);
			System.out.println("identification: "+identificationString);
			System.out.println("dontFragment: "+dontFragment);
			System.out.println("moreFragments: "+moreFragments);
			System.out.println("fragmentOffset: "+fragmentOffsetString);
			System.out.println("TTL: "+TTLstring);
			System.out.println("protocol: "+protocolString);
			System.out.println("headerChecksum: "+headerChecksumString);
			System.out.println("srcIP: "+srcIPstring);
			System.out.println("dstIP: "+dstIPstring);
			if (IHLi>5) {
				System.out.println("options: "+IPoptionsString);
			}
			else {
				System.out.println("There are no IP options.");
			}
			if (IPpayloadLengthI>0) {
				System.out.println("IPpayload (length="+IPpayloadLengthI+"):\n"+
						IPpayloadString);
			}
			else {
				System.out.println("There is no IP payload.");
			}
		}
	}

	public String IPprettyParse () {

		String parseS = "";

		parseS += "IP\n"
				+ "==================================\n";
		if (version==null) {
			parseS += "IP packet not parsed.\n";
		}
		else {
			parseS += "version: "+versionString.charAt(1)+"\n";
			parseS += "IHL: "+IHLstring.charAt(1)+"\n";
			parseS += "TOS: "+TOSstring+"\n";
			parseS += "IPtotalLength: "+IPtotalLengthI+"\n";
			parseS += "identification: "+identificationI+"\n";
			parseS += "dontFragment: "+dontFragment+"\n";
			parseS += "moreFragments: "+moreFragments+"\n";
			parseS += "fragmentOffset: "+fragmentOffsetI+"\n";
			parseS += "TTL: "+Integer.parseInt(TTLstring, 16)+"\n";

			if (protocolString.equals("01")) {
				parseS += "protocol: ICMP (1)\n";
			}
			else if (protocolString.equals("06")) {
				parseS += "protocol: TCP (6)\n";
			}
			else if (protocolString.equals("11")) {
				parseS += "protocol: UDP (17)\n";
			}
			else {
				parseS += "protocol: "+Integer.parseInt(protocolString, 16)+"\n";
			}

			parseS += "headerChecksum: 0x"+headerChecksumString.replaceAll
					("\\s", "");
			if (checkChecksum()) {
				parseS += " ✓";
			}
			else {
				parseS += " X";
			}
			parseS += "\n";

			// add IP addresses in dot notation
			parseS += "srcIP: "+srcIPdottedString;
			parseS += "\ndstIP: "+dstIPdottedString+"\n";

			if (IHLi>5) {
				parseS += "options (length="+IPoptionsLengthI+"):\n"+
						getDriver().byteArrayToString(IPoptions)+"\n";
			}
			else {
				parseS += "There are no IP options.\n";
			}
			if (IPpayloadLengthI>0) {
				parseS += "IPpayload length: "+IPpayloadLengthI+"\n";

				parseS += "IPpayload:\n"+
						getDriver().byteArrayToString(IPpayload);
			}
			else {
				parseS += "There is no IP payload.\n";
			}
		}
		return parseS;
	}

	public boolean isFragment() {
		if (moreFragments || fragmentOffsetI != 0) {
			return true;
		}
		return false;
	}
	
	public byte[] getVersion() {
		return version;
	}

	public void setVersion(byte[] version) {
		this.version = version;
	}

	public byte[] getIHL() {
		return IHL;
	}

	public void setIHL(byte[] iHL) {
		IHL = iHL;
	}

	public byte[] getTOS() {
		return TOS;
	}

	public void setTOS(byte[] dSCP) {
		TOS = dSCP;
	}

	public byte[] getIPtotalLength() {
		return IPtotalLength;
	}

	public void setIPtotalLength(byte[] iPtotalLength) {
		IPtotalLength = iPtotalLength;
	}

	public byte[] getIdentification() {
		return identification;
	}

	public void setIdentification(byte[] identification) {
		this.identification = identification;
	}

	public boolean isDontFragment() {
		return dontFragment;
	}

	public void setDontFragment(boolean dontFragment) {
		this.dontFragment = dontFragment;
	}

	public boolean isMoreFragments() {
		return moreFragments;
	}

	public void setMoreFragments(boolean moreFragments) {
		this.moreFragments = moreFragments;
	}

	public boolean isReservedBit() {
		return reservedBit;
	}

	public void setReservedBit(boolean reservedBit) {
		this.reservedBit = reservedBit;
	}

	public byte[] getFragmentOffset() {
		return fragmentOffset;
	}

	public void setFragmentOffset(byte[] fragmentOffset) {
		this.fragmentOffset = fragmentOffset;
	}

	public byte[] getTTL() {
		return TTL;
	}

	public void setTTL(byte[] tTL) {
		TTL = tTL;
	}

	public byte[] getProtocol() {
		return protocol;
	}

	public void setProtocol(byte[] protocol) {
		this.protocol = protocol;
	}

	public byte[] getHeaderChecksum() {
		return headerChecksum;
	}

	public void setHeaderChecksum(byte[] headerChecksum) {
		this.headerChecksum = headerChecksum;
	}

	public byte[] getSrcIP() {
		return srcIP;
	}

	public void setSrcIP(byte[] srcIP) {
		this.srcIP = srcIP;
	}

	public byte[] getDstIP() {
		return dstIP;
	}

	public void setDstIP(byte[] dstIP) {
		this.dstIP = dstIP;
	}

	public byte[] getIPoptions() {
		return IPoptions;
	}

	public void setIPoptions(byte[] iPoptions) {
		IPoptions = iPoptions;
	}

	public byte[] getIPpayload() {
		return IPpayload;
	}

	public void setIPpayload(byte[] iPpayload) {
		IPpayload = iPpayload;
	}

	public String getVersionString() {
		return versionString;
	}

	public void setVersionString(String versionString) {
		this.versionString = versionString;
	}

	public String getIHLstring() {
		return IHLstring;
	}

	public void setIHLstring(String iHLstring) {
		IHLstring = iHLstring;
	}

	public String getTOSstring() {
		return TOSstring;
	}

	public void setTOSstring(String dSCPstring) {
		TOSstring = dSCPstring;
	}

	public String getIPtotalLengthString() {
		return IPtotalLengthString;
	}

	public void setIPtotalLengthString(String iPtotalLengthString) {
		IPtotalLengthString = iPtotalLengthString;
	}

	public String getIdentificationString() {
		return identificationString;
	}

	public void setIdentificationString(String identificationString) {
		this.identificationString = identificationString;
	}

	public String getFragmentOffsetString() {
		return fragmentOffsetString;
	}

	public void setFragmentOffsetString(String fragmentOffsetString) {
		this.fragmentOffsetString = fragmentOffsetString;
	}

	public String getTTLstring() {
		return TTLstring;
	}

	public void setTTLstring(String tTLstring) {
		TTLstring = tTLstring;
	}

	public String getProtocolString() {
		return protocolString;
	}

	public void setProtocolString(String protocolString) {
		this.protocolString = protocolString;
	}

	public String getHeaderChecksumString() {
		return headerChecksumString;
	}

	public void setHeaderChecksumString(String headerChecksumString) {
		this.headerChecksumString = headerChecksumString;
	}

	public String getSrcIPstring() {
		return srcIPstring;
	}

	public void setSrcIPstring(String srcIPstring) {
		this.srcIPstring = srcIPstring;
	}

	public String getDstIPstring() {
		return dstIPstring;
	}

	public void setDstIPstring(String dstIPstring) {
		this.dstIPstring = dstIPstring;
	}

	public String getIPoptionsString() {
		return IPoptionsString;
	}

	public void setIPoptionsString(String iPoptionsString) {
		IPoptionsString = iPoptionsString;
	}

	public String getIPpayloadString() {
		return IPpayloadString;
	}

	public void setIPpayloadString(String iPpayloadString) {
		IPpayloadString = iPpayloadString;
	}

	public String getSrcIPdottedString() {
		return srcIPdottedString;
	}

	public void setSrcIPdottedString(String srcIPdottedString) {
		this.srcIPdottedString = srcIPdottedString;
	}

	public String getDstIPdottedString() {
		return dstIPdottedString;
	}

	public void setDstIPdottedString(String dstIPdottedString) {
		this.dstIPdottedString = dstIPdottedString;
	}

	public int getIdentificationI() {
		return identificationI;
	}

	public void setIdentificationI(int identificationI) {
		this.identificationI = identificationI;
	}

	public int getFragmentOffsetI() {
		return fragmentOffsetI;
	}

	public void setFragmentOffsetI(int fragmentOffsetI) {
		this.fragmentOffsetI = fragmentOffsetI;
	}

	public int getIHLi() {
		return IHLi;
	}

	public void setIHLi(int iHLi) {
		IHLi = iHLi;
	}

	public int getIPtotalLengthI() {
		return IPtotalLengthI;
	}

	public void setIPtotalLengthI(int iPtotalLengthI) {
		IPtotalLengthI = iPtotalLengthI;
	}

	public int getIPoptionsLengthI() {
		return IPoptionsLengthI;
	}

	public void setIPoptionsLengthI(int iPoptionsLengthI) {
		IPoptionsLengthI = iPoptionsLengthI;
	}

	public int getIPpayloadLengthI() {
		return IPpayloadLengthI;
	}

	public void setIPpayloadLengthI(int iPpayloadLengthI) {
		IPpayloadLengthI = iPpayloadLengthI;
	}
}
