/*
 * Snort Rule
 * 5/5/16 - 5/X/16
 * 
 * by Matt Weeden
 * 
 * CS 7473 Network Security
 * Dr. Mauricio Papa
 * 
 */

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.HashSet;
import java.util.LinkedList;

public class SnortRule {

	private final String syntaxErrorNote = "There is an error in your Snort rule syntax.\n"
			+ "General format:\n"
			+ "action protocol (ip/mask|any) ([port1]:port2 | any) (->|<>) (ip/mask|any) "
			+ "[[port1]:port2 | any) [(options)]"
			+ "See http://manual-snort-org.s3-website-us-east-1.amazonaws.com/node27.html for more "
			+ "syntax information.";

	private String ruleStr;

	// action is false for a pass rule and true for an alert rule
	private boolean action;
	private String protocol;

	private String srcIP;
	private int srcMask;
	private int srcPort1;
	private int srcPort2;

	// direction is false for one-way flow and true for bidirectional flow
	private boolean direction;

	private String dstIP;
	private int dstMask;
	private int dstPort1;
	private int dstPort2;

	// snort rule options
	private String msgO;
	private String logtoO;
	private int ttlO;
	private int tosO;
	private int idO;
	private int fragoffsetO;
	private String ipoptsO;
	private String fragbitsModO;
	private String fragbitsBitsO;
	private int dsizeMinO;
	private int dsizeMaxO;
	private String flagsModO;
	private String flagsBitsO;
	private long seqO;
	private long ackO;
	private int itypeO;
	private int icodeO;
	private boolean contentNotO;
	private String contentO;
	private boolean sameIPo;
	private int sid0;

	public SnortRule(String ruleString) {

		initOptions();

		ruleStr = ruleString;

		try {

			// check that at least 6 spaces are present
			if ((ruleString.length() - ruleString.replaceAll(" ", "").length()) < 6) {
				System.out.println(syntaxErrorNote);
				System.exit(1);
			}

			// capture action
			if (ruleString.startsWith("alert")) {
				action = true;
			}
			else if (ruleString.startsWith("pass")) {
				action = false;
			}
			else {
				System.out.println(syntaxErrorNote);
				System.exit(1);
			}

			ruleString = ruleString.substring(ruleString.indexOf(" ")+1);

			// capture protocol
			HashSet<String> validProtocols = new HashSet<String>();
			validProtocols.add("arp");
			validProtocols.add("ip");
			validProtocols.add("tcp");
			validProtocols.add("udp");
			validProtocols.add("icmp");

			if (validProtocols.contains(ruleString.substring(0, ruleString.indexOf(" ")))) {
				protocol = ruleString.substring(0, ruleString.indexOf(" "));
			}
			else {
				System.out.println(syntaxErrorNote);
				System.exit(1);
			}

			ruleString = ruleString.substring(ruleString.indexOf(" ")+1);

			// capture src ip address/mask
			srcIP = ruleString.substring(0, ruleString.indexOf(" "));
			// check for mask
			if (srcIP.contains("/")) {
				srcMask = Integer.parseInt(srcIP.split("/", 2)[1]);
				srcIP = srcIP.split("/", 2)[0];
			}
			else {
				srcMask = 0;
			}
			// check for IP dots
			if (srcIP.length() - srcIP.replaceAll("\\.", "").length() == 3) {
				for (String number : srcIP.split(".")) {
					if (!number.matches("\\d+")) {
						System.out.println(syntaxErrorNote);
						System.exit(1);
					}
				}
			}
			// check for "any"
			else if (!srcIP.equals("any")) {
				System.out.println(syntaxErrorNote);
				System.exit(1);
			}

			ruleString = ruleString.substring(ruleString.indexOf(" ")+1);

			// capture src port range
			String ports = ruleString.substring(0, ruleString.indexOf(" "));
			if (ports.contains(":")) {
				if (ports.startsWith(":")) {
					srcPort1 = -1;
					srcPort2 = Integer.parseInt(ports.substring(1));
				}
				else {
					srcPort1 = Integer.parseInt(ports.split(":")[0]);
					srcPort2 = Integer.parseInt(ports.split(":")[1]);
				}
			}
			else if (ports.equals("any")) {
				srcPort1 = -1;
				srcPort2 = -1;
			}
			else {
				srcPort1 = Integer.parseInt(ports);
				srcPort2 = -1;
			}

			ruleString = ruleString.substring(ruleString.indexOf(" ")+1);

			// capture direction
			if (ruleString.startsWith("<")) {
				direction = true;
			}
			else if (ruleString.startsWith("-")) {
				direction = false;
			}
			else {
				System.out.println(syntaxErrorNote);
				System.exit(1);
			}

			ruleString = ruleString.substring(ruleString.indexOf(" ")+1);

			// capture dst ip address/mask
			dstIP = ruleString.substring(0, ruleString.indexOf(" "));
			// check for mask
			if (dstIP.contains("/")) {
				dstMask = Integer.parseInt(dstIP.split("/", 2)[1]);
				dstIP = dstIP.split("/", 2)[0];
			}
			else {
				dstMask = 0;
			}
			// check for IP dots
			if (dstIP.length() - dstIP.replaceAll("\\.", "").length() == 3) {
				for (String number : dstIP.split(".")) {
					if (!number.matches("\\d+")) {
						System.out.println(syntaxErrorNote);
						System.exit(1);
					}
				}
			}
			// check for "any"
			else if (!dstIP.equals("any")) {
				System.out.println(syntaxErrorNote);
				System.exit(1);
			}

			ruleString = ruleString.substring(ruleString.indexOf(" ")+1);

			// capture dst port range
			//   NOTE: this may be the final word in the rule
			if (ruleString.contains(" ")) {
				ports = ruleString.substring(0, ruleString.indexOf(" "));
			}
			else {
				ports = ruleString;
			}
			if (ports.contains(":")) {
				if (ports.startsWith(":")) {
					dstPort1 = -1;
					dstPort2 = Integer.parseInt(ports.substring(1));
				}
				else {
					dstPort1 = Integer.parseInt(ports.split(":")[0]);
					dstPort2 = Integer.parseInt(ports.split(":")[1]);
				}
			}
			else if (ports.equals("any")) {
				dstPort1 = -1;
				dstPort2 = -1;
			}
			else {
				dstPort1 = Integer.parseInt(ports);
				dstPort2 = -1;
			}

			// remove options parentheses if any
			ruleString = ruleString.replaceAll("[()]", "");

			// capture options
			while (ruleString.contains(" ")) {

				ruleString = ruleString.substring(ruleString.indexOf(" ")+1);

				if (ruleString.startsWith("msg:")) {
					msgO = ruleString.split("\"")[1];
				}
				else if (ruleString.startsWith("logto:")) {
					logtoO = ruleString.split("\"")[1];
				}
				else if (ruleString.startsWith("ttl:")) {
					ttlO = Integer.parseInt(ruleString.split("[: ;]+")[1]);
				}
				else if (ruleString.startsWith("tos:")) {
					tosO = Integer.parseInt(ruleString.split("[: ;]+")[1]);
				}
				else if (ruleString.startsWith("id:")) {
					idO = Integer.parseInt(ruleString.split("[: ;]+")[1]);
				}
				else if (ruleString.startsWith("fragoffset:")) {
					fragoffsetO = Integer.parseInt(ruleString.split("[: ;]+")[1]);
				}
				else if (ruleString.startsWith("ipopts:")) {
					ipoptsO = ruleString.split("[: ;]+")[1];
				}
				else if (ruleString.startsWith("fragbits:")) {
					fragbitsModO = ruleString.split("[: ;]+")[1];
					fragbitsModO = fragbitsModO.replaceAll("\\w", "");

					fragbitsBitsO = ruleString.split("[: ;]+")[1];
					fragbitsBitsO = fragbitsBitsO.replaceAll("[^MDR]", "");
				}
				else if (ruleString.startsWith("dsize:")) {
					String dsizeO = ruleString.split("[: ;]+")[1];

					if (dsizeO.contains("<>")) {
						dsizeMinO = Integer.parseInt(dsizeO.substring(0, dsizeO.indexOf("<")));
						dsizeMaxO = Integer.parseInt(dsizeO.substring(dsizeO.indexOf(">")+1));
					}
					else if (dsizeO.startsWith(">")) {
						dsizeMinO = Integer.parseInt(dsizeO.substring(1));
						dsizeMaxO = Integer.MAX_VALUE;
					}
					else if (dsizeO.startsWith("<")) {
						dsizeMinO = Integer.MAX_VALUE;
						dsizeMaxO = Integer.parseInt(dsizeO.substring(1));
					}
					else {
						System.out.println(syntaxErrorNote);
						System.exit(1);
					}
				}
				else if (ruleString.startsWith("flags:")) {
					flagsModO = ruleString.split("[: ;]+")[1];
					flagsModO = flagsModO.replaceAll("\\w", "");

					flagsBitsO = ruleString.split("[: ;]++")[1];
					flagsBitsO = flagsBitsO.replaceAll("[^FSRPAUCE0]", "");
				}
				else if (ruleString.startsWith("seq:")) {
					seqO = Long.parseLong(ruleString.split("[: ;]+")[1]);
				}
				else if (ruleString.startsWith("ack:")) {
					ackO = Long.parseLong(ruleString.split("[: ;]+")[1]);
				}
				else if (ruleString.startsWith("itype:")) {
					itypeO = Integer.parseInt(ruleString.split("[: ;]+")[1]);
				}
				else if (ruleString.startsWith("icode:")) {
					icodeO = Integer.parseInt(ruleString.split("[: ;]+")[1]);
				}
				else if (ruleString.startsWith("content:")) {
					contentO = ruleString.split("[:;]+")[1];
					contentO = contentO.trim();

					if (contentO.startsWith("!")) {
						contentNotO = true;
					}
					contentO = contentO.split("\"")[1];
					// make sure bars are used correctly if at all
					if (contentO.startsWith("|") && !contentO.endsWith("|")) {
						System.out.println(syntaxErrorNote);
						System.exit(1);
					}
				}
				else if (ruleString.startsWith("sameip;")) {
					sameIPo = true;
				}
				else if (ruleString.startsWith("sid:")) {
					sid0 = Integer.parseInt(ruleString.split("[: ;]+")[1]);
				}	
			}

		}
		catch (Exception e) {
			System.out.println(syntaxErrorNote);
			System.exit(1);
		}


	}

	private void initOptions() {
		// snort rule options
		msgO = "";
		logtoO = "";
		ttlO = -1;
		tosO = -1;
		idO = -1;
		fragoffsetO = -1;
		ipoptsO = "";
		fragbitsModO = "";
		fragbitsBitsO = "";
		dsizeMinO = Integer.MIN_VALUE;
		dsizeMaxO = Integer.MAX_VALUE;
		flagsModO = "";
		flagsBitsO = "";
		seqO = -1;
		ackO = -1;
		itypeO = -1;
		icodeO = -1;
		contentNotO = false;
		contentO = "";
		sameIPo = false;
		sid0 = -1;
	}

	public static LinkedList<String> readRules(String filename) {
		LinkedList<String> rules = new LinkedList<String>();
		BufferedReader br;

		try {
			File rulesFile = new File(filename);
			br = new BufferedReader(new FileReader(rulesFile));

			String rule;
			while ((rule = br.readLine()) != null) {
				rules.add(rule);
			}
		}
		catch (Exception e){
			e.printStackTrace();
		}

		return rules;
	}

	public static void checkRules(IPPacket ipp, LinkedList<SnortRule> rules) {
		SimplePacketDriver driver = new SimplePacketDriver();
		
		int rulesLen = rules.size();
		SnortRule sr;
		
		for (int i=0; i<rulesLen; i++) {
			sr = rules.get(i);
			
			//
			// this series of checks search for mismatches between the rule and the packet
			////////////////////////////////////////////////////////////////////////////////////////
			
			// protocol
			if (sr.getProtocol().equals("ip") && 
					Packet.packetCharacterizer(ipp.getBytes()).equals("arp")) {
				continue;
			}
			if (!sr.getProtocol().equals(Packet.packetCharacterizer(ipp.getBytes()))) {
				continue;
			}

			// ip addresses
			if (!sr.getSrcIP().equals("any")) {
				if (!checkIP(ipp.getSrcIPdottedString(), sr.getSrcIP(), sr.getSrcMask())) {
					continue;
				}
				// check the opposite if it's a bidirectional rule
				if (sr.isDirection()) {
					if (!checkIP(ipp.getDstIPdottedString(), sr.getSrcIP(), sr.getSrcMask())) {
						continue;
					}
				}
			}
			if (!sr.getDstIP().equals("any")) {
				if (!checkIP(ipp.getDstIPdottedString(), sr.getDstIP(), sr.getDstMask())) {
					continue;
				}
				// check the opposite if it's a bidirectional rule
				if (sr.isDirection()) {
					if (!checkIP(ipp.getSrcIPdottedString(), sr.getDstIP(), sr.getDstMask())) {
						continue;
					}
				}
			}

			// ports
			if (Packet.packetCharacterizer(ipp.getBytes()).equals("tcp") ||
					Packet.packetCharacterizer(ipp.getBytes()).equals("udp")) {
				if (!(sr.getSrcPort1() == -1 && sr.getSrcPort2() == -1)) {
					if (!checkPort(ipp, true, sr.getSrcPort1(), sr.getSrcPort2())) {
						continue;
					}
					// check the opposites if it's a bidirectional rule
					if (sr.isDirection()) {
						if (!checkPort(ipp, false, sr.getSrcPort1(), sr.getSrcPort2())) {
							continue;
						}
					}
				}
				if (!(sr.getDstPort1() == -1 && sr.getDstPort2() == -1)) {
					if (!checkPort(ipp, false, sr.getDstPort1(), sr.getDstPort2())) {
						continue;
					}
					// check the opposites if it's a bidirectional rule
					if (sr.isDirection()) {
						if (!checkPort(ipp, true, sr.getDstPort1(), sr.getDstPort2())) {
							continue;
						}
					}
				}
			}

			//
			// options
			/////////////////////////////////////////////////////////////////////////////////////////

			// time to live
			if (sr.getTtlO() > -1) {
				if (sr.getTtlO() != Integer.parseInt(ipp.getTTLstring(), 16)) {
					continue;
				}
			}

			// type of service
			if (sr.getTosO() > -1) {
				if (sr.getTosO() != Integer.parseInt(ipp.getTOSstring(), 16)) {
					continue;
				}
			}

			// IP fragment identification
			if (sr.getIdO() > -1) {
				if (sr.getIdO() != ipp.getIdentificationI()) {
					continue;
				}
			}

			// fragment offset
			if (sr.getFragoffsetO() > -1) {
				if (sr.getFragoffsetO() != ipp.getFragmentOffsetI()) {
					continue;
				}
			}

			// IP options
			//   NOTE: this is a simplification, since IPPacket does not parse IP options
			if (sr.getipoptsO().length() > 0) {
				if (ipp.getIPoptionsLengthI() == 0) {
					continue;
				}
			}

			// fragmentation bits
			if (sr.getFragbitsBitsO().length() > 0) {
				// the OR modifier
				if (sr.getFragbitsModO().contains("*")) {
					if (sr.getFragbitsModO().contains("!")) {
						if (sr.getFragbitsBitsO().contains("M") && ipp.isMoreFragments()) {
							if (sr.getFragbitsBitsO().length() == 1) {
								continue;
							}
							else {
								if (sr.getFragbitsBitsO().contains("D") && ipp.isDontFragment()) {
									if (sr.getFragbitsBitsO().length() == 2) {
										continue;
									}
									else {
										if (sr.getFragbitsBitsO().contains("R") && 
												ipp.isReservedBit()) {
											continue;
										}
									}
								}
								else if (sr.getFragbitsBitsO().length() == 2 &&
										sr.getFragbitsBitsO().contains("R") && 
										ipp.isReservedBit()) {
									continue;
								}
							}
						}
					}
					else {
						if (sr.getFragbitsBitsO().contains("M") && !ipp.isMoreFragments()) {
							if (sr.getFragbitsBitsO().length() == 1) {
								continue;
							}
							else {
								if (sr.getFragbitsBitsO().contains("D") && !ipp.isDontFragment()) {
									if (sr.getFragbitsBitsO().length() == 2) {
										continue;
									}
									else {
										if (sr.getFragbitsBitsO().contains("R") &&
												!ipp.isReservedBit()) {
											continue;
										}
									}
								}
								else if (sr.getFragbitsBitsO().length() == 2 &&
										sr.getFragbitsBitsO().contains("R") &&
										!ipp.isReservedBit()) {
									continue;
								}
							}
						}
					}
				}
				// the AND modifier ("+")
				else {
					if (sr.getFragbitsModO().contains("!")) {
						if (sr.getFragbitsBitsO().contains("M") && ipp.isMoreFragments()) {
							continue;
						}
						if (sr.getFragbitsBitsO().contains("D") && ipp.isDontFragment()) {
							continue;
						}
						if (sr.getFragbitsBitsO().contains("R") && ipp.isReservedBit()) {
							continue;
						}
					}
					else {
						if (sr.getFragbitsBitsO().contains("M") && !ipp.isMoreFragments()) {
							continue;
						}
						if (sr.getFragbitsBitsO().contains("D") && !ipp.isDontFragment()) {
							continue;
						}
						if (sr.getFragbitsBitsO().contains("R") && !ipp.isReservedBit()) {
							continue;
						}
					}
				}
			}

			// datagram size
			if (ipp.getIPpayloadLengthI() < sr.getDsizeMinO() ||
					ipp.getIPpayloadLengthI() > sr.getDsizeMaxO()) {
				continue;
			}

			//
			// TCP-related options
			////////////////////////////////////////////////////////////////////////////////////////
			if (Packet.packetCharacterizer(ipp.getBytes()).equals("tcp")) {
				TCPPacket tcpp = new TCPPacket(ipp.getBytes());
				tcpp.parseTCP();

				// flags
				if (sr.getFlagsBitsO().length() > 0) {
					// the OR modifier
					if (sr.getFlagsModO().contains("*")) {
						boolean matches = false;
						if (sr.getFlagsModO().contains("!")) {
							if (sr.getFlagsBitsO().contains("F") && !tcpp.isFIN()) {
								matches = true;
							}
							if (!matches && sr.getFlagsBitsO().contains("S") && !tcpp.isSYN()) {
								matches = true;
							}
							if (!matches && sr.getFlagsBitsO().contains("R") && !tcpp.isRST()) {
								matches = true;
							}
							if (!matches && sr.getFlagsBitsO().contains("P") && !tcpp.isPSH()) {
								matches = true;
							}
							if (!matches && sr.getFlagsBitsO().contains("A") && !tcpp.isACK()) {
								matches = true;
							}
							if (!matches && sr.getFlagsBitsO().contains("U") && !tcpp.isURG()) {
								matches = true;
							}
							if (!matches) {
								continue;
							}
						}
						else {
							if (sr.getFlagsBitsO().contains("F") && tcpp.isFIN()) {
								matches = true;
							}
							if (!matches && sr.getFlagsBitsO().contains("S") && tcpp.isSYN()) {
								matches = true;
							}
							if (!matches && sr.getFlagsBitsO().contains("R") && tcpp.isRST()) {
								matches = true;
							}
							if (!matches && sr.getFlagsBitsO().contains("P") && tcpp.isPSH()) {
								matches = true;
							}
							if (!matches && sr.getFlagsBitsO().contains("A") && tcpp.isACK()) {
								matches = true;
							}
							if (!matches && sr.getFlagsBitsO().contains("U") && tcpp.isURG()) {
								matches = true;
							}
							if (!matches) {
								continue;
							}
						}
					}
					// the AND modifier ("+")
					else {
						if (sr.getFlagsModO().contains("!")) {
							if (sr.getFlagsBitsO().contains("F") && tcpp.isFIN()) {
								continue;
							}
							if (sr.getFlagsBitsO().contains("S") && tcpp.isSYN()) {
								continue;
							}
							if (sr.getFlagsBitsO().contains("R") && tcpp.isRST()) {
								continue;
							}
							if (sr.getFlagsBitsO().contains("P") && tcpp.isPSH()) {
								continue;
							}
							if (sr.getFlagsBitsO().contains("A") && tcpp.isACK()) {
								continue;
							}
							if (sr.getFlagsBitsO().contains("U") && tcpp.isURG()) {
								continue;
							}
						}
						else {
							if (sr.getFlagsBitsO().contains("F") && !tcpp.isFIN()) {
								continue;
							}
							if (sr.getFlagsBitsO().contains("S") && !tcpp.isSYN()) {
								continue;
							}
							if (sr.getFlagsBitsO().contains("R") && !tcpp.isRST()) {
								continue;
							}
							if (sr.getFlagsBitsO().contains("P") && !tcpp.isPSH()) {
								continue;
							}
							if (sr.getFlagsBitsO().contains("A") && !tcpp.isACK()) {
								continue;
							}
							if (sr.getFlagsBitsO().contains("U") && !tcpp.isURG()) {
								continue;
							}
						}
					}
				}
				
				// sequence number
				if (sr.getSeqO() > -1) {
					if (sr.getSeqO() != Long.parseLong(tcpp.getSequenceNumString()
							.replaceAll("\\s", ""), 16)) {
						continue;
					}
				}
				
				// acknowledge number
				if (sr.getAckO() > -1) {
					if (sr.getAckO() != Long.parseLong(tcpp.getACKnumString()
							.replaceAll("\\s", ""), 16)) {
						continue;
					}
				}
			}
			
			//
			// ICMP-related options
			////////////////////////////////////////////////////////////////////////////////////////
			if (Packet.packetCharacterizer(ipp.getBytes()).equals("icmp")) {
				ICMPPacket icmpp = new ICMPPacket(ipp.getBytes());
				icmpp.parseICMP();
				
				// ICMP type
				if (sr.getItypeO() > -1) {
					if (sr.getItypeO() != Integer.parseInt(icmpp.getICMPtypeString(), 16)) {
						continue;
					}
				}
				
				// ICMP code
				if (sr.getIcodeO() > -1) {
					if (sr.getIcodeO() != Integer.parseInt(icmpp.getICMPcodeString(), 16)) {
						continue;
					}
				}
			}
			
			// content
			if (sr.getContentO().length() > 0) {
				if (sr.getContentO().startsWith("|")) {
					String hexNumbersStr = sr.getContentO().replaceAll("[|]", "");
					
					if (sr.iscontentNotO()) {
						if (ipp.getIPpayloadString().contains(hexNumbersStr)) {
							continue;
						}
					}
					else {						
						if (!ipp.getIPpayloadString().contains(hexNumbersStr)) {
							continue;
						}
					}
				}
				else {
					byte[] patternBs = sr.getContentO().getBytes();
					String pattern = "";
					for (int j=0; j<patternBs.length; j++) {
						pattern += driver.byteToHex(patternBs[j]) + " ";
					}
					pattern.trim();
					if (sr.iscontentNotO()) {
						if (ipp.getIPpayloadString().contains(pattern)) {
							continue;
						}
					}
					else {						
						if (!ipp.getIPpayloadString().contains(pattern)) {
							continue;
						}
					}
				}
			}
			
			
			// same IP address
			if (sr.isSameIPo()) {
				if (ipp.getSrcIPdottedString().equals(ipp.getDstIPdottedString())) {
					continue;
				}
			}

			// this code is only reached if the packet matches this rule
			if (sr.isAction()) {
				logPacket(ipp, sr);
			}
		}
	}

	// return true if it matches
	private static boolean checkIP(String packetAddString, String ruleAddString, int ruleMask) {

		try {
			Inet4Address RuleSA = (Inet4Address) InetAddress.getByName(ruleAddString);
			Inet4Address packetSA = (Inet4Address) InetAddress.getByName(packetAddString);

			byte[] b = RuleSA.getAddress();
			int rsaInt = ((b[0] & 0xFF) << 24) |
					((b[1] & 0xFF) << 16) |
					((b[2] & 0xFF) << 8)  |
					((b[3] & 0xFF) << 0);
			b = packetSA.getAddress();
			int psaInt = ((b[0] & 0xFF) << 24) |
					((b[1] & 0xFF) << 16) |
					((b[2] & 0xFF) << 8)  |
					((b[3] & 0xFF) << 0);

			int sMask = -1 << (32 - ruleMask);

			if ((rsaInt & sMask) != (psaInt & sMask)) {
				return false;
			}

		} catch (UnknownHostException e) {
			e.printStackTrace();
		}

		return true;
	}

	private static boolean checkPort(IPPacket ipp, boolean type, int port1, int port2) {

		if (Packet.packetCharacterizer(ipp.getBytes()).equals("tcp")) {
			TCPPacket tcpp = new TCPPacket(ipp.getBytes());
			tcpp.parseTCP();

			if (port1 == -1) {
				if (type) {
					if (tcpp.getSPortI() > port2) {
						return false;
					}
				}
				else {
					if (tcpp.getDPortI() > port2) {
						return false;
					}
				}
			}
			else {
				if (type) {
					if (tcpp.getSPortI() < port1) {
						return false;
					}
				}
				else {
					if (tcpp.getDPortI() < port1) {
						return false;
					}
				}
			}
		}
		else if (Packet.packetCharacterizer(ipp.getBytes()).equals("udp")) {
			UDPPacket udpp = new UDPPacket(ipp.getBytes());
			udpp.parseUDP();

			if (port1 == -1) {
				if (type) {
					if (udpp.getSPortI() > port2) {
						return false;
					}
				}
				else {
					if (udpp.getDPortI() > port2) {
						return false;
					}
				}
			}
			else {
				if (type) {
					if (udpp.getSPortI() < port1) {
						return false;
					}
				}
				else {
					if (udpp.getDPortI() < port1) {
						return false;
					}
				}
			}
		}

		return true;
	}

	public static void logPacket(IPPacket ipp, SnortRule sr) {
		
		String alert = "\n\n+++++++ A packet has matched an alert IDS rule. +++++++"
				+ "\nmsg: "+sr.msgO;
				
		System.out.println(alert);
		
		SimplePacketDriver driver = new SimplePacketDriver();

		try {
			String pathS;
			if (sr.getLogtoO().length() > 0) {
				pathS = sr.getLogtoO();
			}
			else {
				pathS = "snort.log.txt";
			}

			Path p = Paths.get(pathS);

			if (Files.notExists(p)) {
				(new File(pathS)).createNewFile();
			}

			String log = "msg: " + sr.getMsgO();
			log += "\nsid: " + sr.getSid0();
			log += "\n" + driver.byteArrayToString(ipp.getBytes());

			Files.write(p, log.getBytes(), StandardOpenOption.APPEND);
		}
		catch (IOException e) {
			e.printStackTrace();
		}
	}

	public String getRuleStr() {
		return ruleStr;
	}

	public void setRuleStr(String ruleString) {
		this.ruleStr = ruleString;
	}

	public boolean isAction() {
		return action;
	}

	public void setAction(boolean action) {
		this.action = action;
	}

	public String getProtocol() {
		return protocol;
	}

	public void setProtocol(String protocol) {
		this.protocol = protocol;
	}

	public String getSrcIP() {
		return srcIP;
	}

	public void setSrcIP(String srcIP) {
		this.srcIP = srcIP;
	}

	public int getSrcMask() {
		return srcMask;
	}

	public void setSrcMask(int srcMask) {
		this.srcMask = srcMask;
	}

	public int getSrcPort1() {
		return srcPort1;
	}

	public void setSrcPort1(int srcPort1) {
		this.srcPort1 = srcPort1;
	}

	public int getSrcPort2() {
		return srcPort2;
	}

	public void setSrcPort2(int srcPort2) {
		this.srcPort2 = srcPort2;
	}

	public boolean isDirection() {
		return direction;
	}

	public void setDirection(boolean direction) {
		this.direction = direction;
	}

	public String getDstIP() {
		return dstIP;
	}

	public void setDstIP(String dstIP) {
		this.dstIP = dstIP;
	}

	public int getDstMask() {
		return dstMask;
	}

	public void setDstMask(int dstMask) {
		this.dstMask = dstMask;
	}

	public int getDstPort1() {
		return dstPort1;
	}

	public void setDstPort1(int dstPort1) {
		this.dstPort1 = dstPort1;
	}

	public int getDstPort2() {
		return dstPort2;
	}

	public void setDstPort2(int dstPort2) {
		this.dstPort2 = dstPort2;
	}

	public String getMsgO() {
		return msgO;
	}

	public void setMsgO(String msgO) {
		this.msgO = msgO;
	}

	public String getLogtoO() {
		return logtoO;
	}

	public void setLogtoO(String logtoO) {
		this.logtoO = logtoO;
	}

	public int getTtlO() {
		return ttlO;
	}

	public void setTtlO(int ttlO) {
		this.ttlO = ttlO;
	}

	public int getTosO() {
		return tosO;
	}

	public void setTosO(int tosO) {
		this.tosO = tosO;
	}

	public int getIdO() {
		return idO;
	}

	public void setIdO(int idO) {
		this.idO = idO;
	}

	public int getFragoffsetO() {
		return fragoffsetO;
	}

	public void setFragoffsetO(int fragoffsetO) {
		this.fragoffsetO = fragoffsetO;
	}

	public String getipoptsO() {
		return ipoptsO;
	}

	public void setipoptsO(String ipoptsO) {
		this.ipoptsO = ipoptsO;
	}

	public String getFragbitsModO() {
		return fragbitsModO;
	}

	public void setFragbitsModO(String fragbitsModO) {
		this.fragbitsModO = fragbitsModO;
	}

	public String getFragbitsBitsO() {
		return fragbitsBitsO;
	}

	public void setFragbitsBitsO(String fragbitsBitsO) {
		this.fragbitsBitsO = fragbitsBitsO;
	}

	public int getDsizeMinO() {
		return dsizeMinO;
	}

	public void setDsizeMinO(int dsizeMinO) {
		this.dsizeMinO = dsizeMinO;
	}

	public int getDsizeMaxO() {
		return dsizeMaxO;
	}

	public void setDsizeMaxO(int dsizeMaxO) {
		this.dsizeMaxO = dsizeMaxO;
	}

	public String getFlagsModO() {
		return flagsModO;
	}

	public void setFlagsModO(String flagsModO) {
		this.flagsModO = flagsModO;
	}

	public String getFlagsBitsO() {
		return flagsBitsO;
	}

	public void setFlagsBitsO(String flagsBitsO) {
		this.flagsBitsO = flagsBitsO;
	}

	public long getSeqO() {
		return seqO;
	}

	public void setSeqO(int seqO) {
		this.seqO = seqO;
	}

	public long getAckO() {
		return ackO;
	}

	public void setAckO(int ackO) {
		this.ackO = ackO;
	}

	public int getItypeO() {
		return itypeO;
	}

	public void setItypeO(int itypeO) {
		this.itypeO = itypeO;
	}

	public int getIcodeO() {
		return icodeO;
	}

	public void setIcodeO(int icodeO) {
		this.icodeO = icodeO;
	}

	public boolean iscontentNotO() {
		return contentNotO;
	}

	public void setcontentNotO(boolean contentNotO) {
		this.contentNotO = contentNotO;
	}

	public String getContentO() {
		return contentO;
	}

	public void setContentO(String contentO) {
		this.contentO = contentO;
	}

	public boolean isSameIPo() {
		return sameIPo;
	}

	public void setSameIPo(boolean sameIPo) {
		this.sameIPo = sameIPo;
	}

	public int getSid0() {
		return sid0;
	}

	public void setSid0(int sid0) {
		this.sid0 = sid0;
	}

	public String getSyntaxErrorNote() {
		return syntaxErrorNote;
	}


}
