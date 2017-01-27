/*
 * Packet Sniffer
 * 2/3/16 - 3/15/16
 * 
 * by Matt Weeden
 * 
 * CS 7473 Network Security
 * Dr. Mauricio Papa
 * 
 */

import java.io.BufferedReader;
import java.io.Console;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedList;

class ConsoleThread extends Thread {

	public void run() {		
		Console co = System.console();

		while(true) {
			if (co.readLine().equals("q")) {
				break;
			}
		}
		System.exit(1);
	}
}

public class PacketParser {

	// used to sniff packets on an interface, though, several methods use the driver to 
	//   convert from bytes to hex strings
	private static SimplePacketDriver driver = new SimplePacketDriver();

	private static ArrayList<FragmentedPacket> fPackets = new ArrayList<FragmentedPacket>();

	//
	//  Main
	////////////////////////////////////////////////////////////////////////////////////////////////
	public static void main(String args[]) {

		//tester();

		// process command line arguments
		HashMap<String, String> argsHash = new HashMap<>(1);
		argsHash = PPArgParser.parse(args);

		// set up PrintWriter if output file option is specified
		PrintWriter printWriter=null;
		if (!argsHash.get("outfile").equals("-1")) {
			try {
				printWriter = new PrintWriter
						(new FileOutputStream(new File(argsHash.get("outfile"))), true);
			} catch (Exception e) {
				System.out.println("Unable to open or create the output file.");
				System.exit(1);;
			}
		}

		// read and parse Snort rules
		LinkedList<String> rulesStrs = SnortRule.readRules("rules.txt");
		LinkedList<SnortRule> rules = new LinkedList<SnortRule>();
		int rulesLen = rulesStrs.size();		
		SnortRule sr;

		for (int i=0; i<rulesLen; i++) {
			sr = new SnortRule(rulesStrs.pop());
			rules.add(sr);
		}

		ArrayList<byte[]> packets = null;

		//
		// read packet from file
		///////////////////////////////////////////////////////////////////////////////////
		if (!argsHash.get("infile").equals("-1")) {
			BufferedReader br = openFile(argsHash.get("infile"));

			// read and parse packets from the whole file
			if (argsHash.get("count").equals("-1")) {
				// read an initial packet
				packets = readPackets(br, 1);
				int count = 1;
				while (packets.size()>0) {
					if (parsePacket(packets.get(0), count, argsHash, printWriter, rules)) {
						count++;
					}
					packets = readPackets(br, 1);
				}
			}
			// read and parse only the number of packets indicated by cmd line argument
			else {
				packets = readPackets(br, 1);
				int count = 0;
				// only increment count if a packet is printed
				while (count<Integer.parseInt(argsHash.get("count")) && packets.size()>0) {
					if (parsePacket(packets.get(0), count, argsHash, printWriter, rules)) {
						count++;
					}
					packets = readPackets(br, 1);
				}
			}

			// close the BufferedReader when finished
			try {
				br.close();
			} catch (Exception e) {
				System.out.println("Unable to properly close file reader.");
				e.printStackTrace();
				System.exit(1);
			}
		}
		//
		// read packet from network interface
		///////////////////////////////////////////////////////////////////////////////////
		else {
			String adapterS = connectToAdapter(driver, 
					Integer.parseInt(argsHash.get("adapter")));

			if (argsHash.get("outfile").equals("-1")) {
				System.out.print(adapterS);
			}
			else {
				printWriter.print(adapterS);
			}

			// read and parse an indefinite number of packets
			if (argsHash.get("count").equals("-1")) {
				// start the thread that will allow user to quit gracefully
				ConsoleThread ct = new ConsoleThread();
				ct.start();
				int count = 0;
				while (true) {
					System.out.print(" ");
					System.out.print("\b");
					packets = readPackets(driver, 1);
					if (parsePacket(packets.get(0), count, argsHash, printWriter, rules)) {
						count++;
					}
					// this if statement is to work around a strange terminal bug when 
					//   using the PrintWriter, but also gives a live update to the terminal how many
					//   parsed packets have been saved to the output file
					if (!argsHash.get("outfile").equals("-1")) {
						for (int i=0; i<35; i++) {
							System.out.print("\b\b");
						}
						System.out.print("\r"+count+" parsed packets have been sent to "
								+argsHash.get("outfile")+"; enter \"q\" to quit.");
					}
				}
			}
			// read and parse only the number of packets indicated by cmd line argument
			else {
				int count = 0;
				while (count<Integer.parseInt(argsHash.get("count"))) {
					System.out.print(" ");
					System.out.print("\b");
					packets = readPackets(driver, 1);
					if (parsePacket(packets.get(0), count, argsHash, printWriter, rules)) {				
						count++;
					}
					// this if statement is to work around a strange terminal bug when 
					//   using the PrintWriter, but also gives a live update to the terminal how 
					//   many parsed packets have been saved to the output file
					if (!argsHash.get("outfile").equals("-1")) {
						System.out.print("\r"+count+" parsed packets have been sent to "
								+argsHash.get("outfile"));
						for (int i=0; i<35; i++) {
							System.out.print("\b\b");
						}
					}
				}
				System.out.println("");
			}
		}
		if (!argsHash.get("outfile").equals("-1")) {
			printWriter.close();			
		}
	}

	private static void parsePackets(ArrayList<byte[]> packets, 
			HashMap<String, String> argH, PrintWriter pw,
			LinkedList<SnortRule> srules) {
		for (int i=0; i<packets.size(); i++) {
			parsePacket(packets.get(i), i, argH, pw, srules);
		}
	}

	// the return value indicates whether or not a packet was printed
	private static boolean parsePacket(byte[] packet, int packetNum, 
			HashMap<String, String> argH, PrintWriter printWriter, 
			LinkedList<SnortRule> sRules) {

		Packet p = new Packet(packet);
		String type = Packet.packetCharacterizer(p.getBytes());

		// initialize packet variables
		ARPPacket arpp;
		IPPacket ipp;
		TCPPacket tcpp;
		UDPPacket udpp;
		ICMPPacket icmpp;

		boolean parsed = false;
		String totalParseS = "";

		//
		// ARP
		////////////////////////////////////////////////////////////////////////////////////////////
		if (type.equals("arp")) {
			// check cmd line "-type" argument
			if (((argH.get("type").toLowerCase()).equals("-1")) 
					|| ((argH.get("type").toLowerCase()).equals("arp"))
					|| ((argH.get("type")).toLowerCase().equals("eth"))) {

				arpp = new ARPPacket(packet);
				totalParseS += arpp.parseARP();

				// check src and dst address arguments
				if (argH.get("sord").equals("1")) {
					if (arpp.getSenderProtocolAddDottedString().equals(argH.get("sAdd"))
							|| arpp.getTargetProtocolAddDottedString().equals
							(argH.get("dAdd"))) {
						totalParseS += arpp.EthPrettyParse(packetNum)+"\n";
						totalParseS += arpp.ARPprettyParse();

						// create and print out descriptor (triple)
						PacketDescriptor pd = new PacketDescriptor(arpp);
						pd.printDescriptor();						

						parsed = true;
					}
				}
				else if (argH.get("sandd").equals("1")) {
					if (arpp.getSenderProtocolAddDottedString().equals(argH.get("sAdd"))
							&& arpp.getTargetProtocolAddDottedString().equals
							(argH.get("dAdd"))) {
						totalParseS += arpp.EthPrettyParse(packetNum)+"\n";
						totalParseS += arpp.ARPprettyParse();

						// create and print out descriptor (triple)
						PacketDescriptor pd = new PacketDescriptor(arpp);
						pd.printDescriptor();

						parsed = true;
					}
				}
				else if (!argH.get("sAdd").equals("-1")) {
					if (arpp.getSenderProtocolAddDottedString().equals(argH.get("sAdd"))) {
						totalParseS += arpp.EthPrettyParse(packetNum)+"\n";
						totalParseS += arpp.ARPprettyParse();

						// create and print out descriptor (triple)
						PacketDescriptor pd = new PacketDescriptor(arpp);
						pd.printDescriptor();

						parsed = true;
					}
				}
				else if (!argH.get("dAdd").equals("-1")) {
					if (arpp.getTargetProtocolAddDottedString().equals(argH.get("dAdd"))) {
						totalParseS += arpp.EthPrettyParse(packetNum)+"\n";
						totalParseS += arpp.ARPprettyParse();

						// create and print out descriptor (triple)
						PacketDescriptor pd = new PacketDescriptor(arpp);
						pd.printDescriptor();

						parsed = true;
					}
				}
				// no src or dst address is specified
				else {
					totalParseS += arpp.EthPrettyParse(packetNum)+"\n";
					totalParseS += arpp.ARPprettyParse();

					// create and print out descriptor (triple)
					PacketDescriptor pd = new PacketDescriptor(arpp);
					pd.printDescriptor();
					
					parsed = true;
				}
			}
		}
		//
		// TCP
		////////////////////////////////////////////////////////////////////////////////////////////
		else if (type.equals("tcp")) {
			// check cmd line "-type" argument
			if ((((argH.get("type").toLowerCase()).equals("-1")) 
					|| ((argH.get("type").toLowerCase()).equals("tcp"))
					|| ((argH.get("type").toLowerCase()).equals("ip"))
					|| ((argH.get("type")).toLowerCase().equals("eth")))) {

				tcpp = new TCPPacket(packet);
				totalParseS += tcpp.parseTCP();

				// verify IP checksum
				//if (tcpp.checkChecksum()) {

					// check at port is inside valid range
					if (tcpp.getSPortI() >= Integer.parseInt(argH.get("sPortRangeLower")) &&
							tcpp.getSPortI() <= Integer.parseInt(argH.get("sPortRangeUpper")) &&
							tcpp.getDPortI() >= Integer.parseInt(argH.get("dPortRangeLower")) &&
							tcpp.getDPortI() <= Integer.parseInt(argH.get("dPortRangeUpper"))) {

						// check src and dst address arguments
						if (argH.get("sord").equals("1")) {
							if (tcpp.getSrcIPdottedString().equals(argH.get("sAdd"))
									|| tcpp.getDstIPdottedString().equals(argH.get("dAdd"))) {
								totalParseS += tcpp.EthPrettyParse(packetNum)+"\n";
								totalParseS += tcpp.IPprettyParse();
								totalParseS += tcpp.TCPprettyParse();

								// if this is a IP-fragmented TCP packet
								if (tcpp.isFragment()) {
									FragmentedPacket fp;
									int datagramIndex = indexOfFragmentedPacket(tcpp);

									// if the fragment is for a new datagram, add it to the fPackets
									//   ArrayList
									if (datagramIndex == -1) {
										fp = new FragmentedPacket();
										fPackets.add(fp);
									}
									else {
										fp = fPackets.get(datagramIndex);
									}
									System.out.println("");

									// add this fragment to the datagram
									boolean completed = fp.addFragment(tcpp);

									// make sure that the fragment offset is not 1, which would indicate
									//   a malicious packet, breaking up the TCP header
									if (tcpp.getFragmentOffsetI() == 1) {
										// mark this datagram as dropped
										fp.setDropped(true);
									}

									if (completed) {
										// create and print out descriptor (triple)
										PacketDescriptor pd = new PacketDescriptor(fp);
										pd.printDescriptor();
										parsePacket(fp.contructCompletedPacket(), 
												-1, argH, printWriter, sRules);
									}
								}
								else {
									SnortRule.checkRules(tcpp, sRules);
								}
								parsed = true;
							}
						}
						else if (argH.get("sandd").equals("1")) {
							if (tcpp.getSrcIPdottedString().equals(argH.get("sAdd"))
									&& tcpp.getDstIPdottedString().equals(argH.get("dAdd"))) {
								totalParseS += tcpp.EthPrettyParse(packetNum)+"\n";
								totalParseS += tcpp.IPprettyParse();
								totalParseS += tcpp.TCPprettyParse();

								// if this is a IP-fragmented TCP packet
								if (tcpp.isFragment()) {
									FragmentedPacket fp;
									int datagramIndex = indexOfFragmentedPacket(tcpp);

									// if the fragment is for a new datagram, add it to the fPackets
									//   ArrayList
									if (datagramIndex == -1) {
										fp = new FragmentedPacket();
										fPackets.add(fp);
									}
									else {
										fp = fPackets.get(datagramIndex);
									}
									System.out.println("");

									// add this fragment to the datagram
									boolean completed = fp.addFragment(tcpp);

									// make sure that the fragment offset is not 1, which would indicate
									//   a malicious packet, breaking up the TCP header
									if (tcpp.getFragmentOffsetI() == 1) {
										// mark this datagram as dropped
										fp.setDropped(true);
									}

									if (completed) {
										// create and print out descriptor (triple)
										PacketDescriptor pd = new PacketDescriptor(fp);
										pd.printDescriptor();
										parsePacket(fp.contructCompletedPacket(), 
												-1, argH, printWriter, sRules);
									}
								}
								else {
									SnortRule.checkRules(tcpp, sRules);
								}
								parsed = true;
							}
						}
						else if (!argH.get("sAdd").equals("-1")) {
							if (tcpp.getSrcIPdottedString().equals(argH.get("sAdd"))) {
								totalParseS += tcpp.EthPrettyParse(packetNum)+"\n";
								totalParseS += tcpp.IPprettyParse();
								totalParseS += tcpp.TCPprettyParse();

								// if this is a IP-fragmented TCP packet
								if (tcpp.isFragment()) {
									FragmentedPacket fp;
									int datagramIndex = indexOfFragmentedPacket(tcpp);

									// if the fragment is for a new datagram, add it to the fPackets
									//   ArrayList
									if (datagramIndex == -1) {
										fp = new FragmentedPacket();
										fPackets.add(fp);
									}
									else {
										fp = fPackets.get(datagramIndex);
									}
									System.out.println("");

									// add this fragment to the datagram
									boolean completed = fp.addFragment(tcpp);

									// make sure that the fragment offset is not 1, which would indicate
									//   a malicious packet, breaking up the TCP header
									if (tcpp.getFragmentOffsetI() == 1) {
										// mark this datagram as dropped
										fp.setDropped(true);
									}

									if (completed) {
										// create and print out descriptor (triple)
										PacketDescriptor pd = new PacketDescriptor(fp);
										pd.printDescriptor();
										parsePacket(fp.contructCompletedPacket(), 
												-1, argH, printWriter, sRules);
									}
								}
								else {
									SnortRule.checkRules(tcpp, sRules);
								}
								parsed = true;
							}
						}
						else if (!argH.get("dAdd").equals("-1")) {
							if (tcpp.getDstIPdottedString().equals(argH.get("dAdd"))) {
								totalParseS += tcpp.EthPrettyParse(packetNum)+"\n";
								totalParseS += tcpp.IPprettyParse();
								totalParseS += tcpp.TCPprettyParse();

								// if this is a IP-fragmented TCP packet
								if (tcpp.isFragment()) {
									FragmentedPacket fp;
									int datagramIndex = indexOfFragmentedPacket(tcpp);

									// if the fragment is for a new datagram, add it to the fPackets
									//   ArrayList
									if (datagramIndex == -1) {
										fp = new FragmentedPacket();
										fPackets.add(fp);
									}
									else {
										fp = fPackets.get(datagramIndex);
									}
									System.out.println("");

									// add this fragment to the datagram
									boolean completed = fp.addFragment(tcpp);

									// make sure that the fragment offset is not 1, which would indicate
									//   a malicious packet, breaking up the TCP header
									if (tcpp.getFragmentOffsetI() == 1) {
										// mark this datagram as dropped
										fp.setDropped(true);
									}

									if (completed) {
										// create and print out descriptor (triple)
										PacketDescriptor pd = new PacketDescriptor(fp);
										pd.printDescriptor();
										parsePacket(fp.contructCompletedPacket(), 
												-1, argH, printWriter, sRules);
									}
								}
								else {
									SnortRule.checkRules(tcpp, sRules);
								}
								parsed = true;
							}
						}
						// no src or dst address is specified
						else {
							totalParseS += tcpp.EthPrettyParse(packetNum)+"\n";
							totalParseS += tcpp.IPprettyParse();
							totalParseS += tcpp.TCPprettyParse();								

							// if this is a IP-fragmented TCP packet
							if (tcpp.isFragment()) {
								FragmentedPacket fp;
								int datagramIndex = indexOfFragmentedPacket(tcpp);

								// if the fragment is for a new datagram, add it to the fPackets
								//   ArrayList
								if (datagramIndex == -1) {
									fp = new FragmentedPacket();
									fPackets.add(fp);
								}
								else {
									fp = fPackets.get(datagramIndex);
								}
								System.out.println("");

								// add this fragment to the datagram
								boolean completed = fp.addFragment(tcpp);

								// make sure that the fragment offset is not 1, which would indicate
								//   a malicious packet, breaking up the TCP header
								if (tcpp.getFragmentOffsetI() == 1) {
									// mark this datagram as dropped
									//	fp.setDropped(true);
								}

								if (completed) {
									// create and print out descriptor (triple)
									PacketDescriptor pd = new PacketDescriptor(fp);
									pd.printDescriptor();
									parsePacket(fp.contructCompletedPacket(), 
											-1, argH, printWriter, sRules);
								}
							}
							else {
								SnortRule.checkRules(tcpp, sRules);
							}
							parsed = true;
						}
					//}
					//else {
				//		totalParseS += "IP checksum incorrect\n";
				//	}
				}
			}
		}
		//
		// UDP
		////////////////////////////////////////////////////////////////////////////////////////////
		else if (type.equals("udp")) {
			// check cmd line "-type" argument
			if (((argH.get("type").toLowerCase()).equals("-1")) 
					|| ((argH.get("type").toLowerCase()).equals("udp"))
					|| ((argH.get("type").toLowerCase()).equals("ip"))
					|| ((argH.get("type")).toLowerCase().equals("eth"))) {
				udpp = new UDPPacket(packet);
				totalParseS += udpp.parseUDP();

				// verify IP checksum
				if (udpp.checkChecksum()) {

					// check at port is inside valid range
					if (udpp.getSPortI() >= Integer.parseInt(argH.get("sPortRangeLower")) &&
							udpp.getSPortI() <= Integer.parseInt(argH.get("sPortRangeUpper")) &&
							udpp.getDPortI() >= Integer.parseInt(argH.get("dPortRangeLower")) &&
							udpp.getDPortI() <= Integer.parseInt(argH.get("dPortRangeUpper"))) {

						// check src and dst address arguments
						if (argH.get("sord").equals("1")) {
							if (udpp.getSrcIPdottedString().equals(argH.get("sAdd"))
									|| udpp.getDstIPdottedString().equals(argH.get("dAdd"))) {
								totalParseS += udpp.EthPrettyParse(packetNum)+"\n";
								totalParseS += udpp.IPprettyParse();
								totalParseS += udpp.UDPprettyParse();

								// if this is a IP-fragmented UDP packet
								if (udpp.isFragment()) {
									FragmentedPacket fp;
									int datagramIndex = indexOfFragmentedPacket(udpp);

									// if the fragment is for a new datagram, add it to the fPackets
									//   ArrayList
									if (datagramIndex == -1) {
										fp = new FragmentedPacket();
										fPackets.add(fp);
									}
									else {
										fp = fPackets.get(datagramIndex);
									}
									System.out.println("");

									// add this fragment to the datagram
									boolean completed = fp.addFragment(udpp);

									if (completed) {
										// create and print out descriptor (triple)
										PacketDescriptor pd = new PacketDescriptor(fp);
										pd.printDescriptor();
										parsePacket(fp.contructCompletedPacket(), 
												-1, argH, printWriter, sRules);
									}
								}
								else {
									SnortRule.checkRules(udpp, sRules);
								}
								parsed = true;
							}
						}
						else if (argH.get("sandd").equals("1")) {
							if (udpp.getSrcIPdottedString().equals(argH.get("sAdd"))
									&& udpp.getDstIPdottedString().equals(argH.get("dAdd"))) {
								totalParseS += udpp.EthPrettyParse(packetNum)+"\n";
								totalParseS += udpp.IPprettyParse();
								totalParseS += udpp.UDPprettyParse();

								// if this is a IP-fragmented UDP packet
								if (udpp.isFragment()) {
									FragmentedPacket fp;
									int datagramIndex = indexOfFragmentedPacket(udpp);

									// if the fragment is for a new datagram, add it to the fPackets
									//   ArrayList
									if (datagramIndex == -1) {
										fp = new FragmentedPacket();
										fPackets.add(fp);
									}
									else {
										fp = fPackets.get(datagramIndex);
									}
									System.out.println("");

									// add this fragment to the datagram
									boolean completed = fp.addFragment(udpp);

									if (completed) {
										// create and print out descriptor (triple)
										PacketDescriptor pd = new PacketDescriptor(fp);
										pd.printDescriptor();
										parsePacket(fp.contructCompletedPacket(), 
												-1, argH, printWriter, sRules);
									}
								}
								else {
									SnortRule.checkRules(udpp, sRules);
								}
								parsed = true;
							}
						}
						else if (!argH.get("sAdd").equals("-1")) {
							if (udpp.getSrcIPdottedString().equals(argH.get("sAdd"))) {
								totalParseS += udpp.EthPrettyParse(packetNum)+"\n";
								totalParseS += udpp.IPprettyParse();
								totalParseS += udpp.UDPprettyParse();

								// if this is a IP-fragmented UDP packet
								if (udpp.isFragment()) {
									FragmentedPacket fp;
									int datagramIndex = indexOfFragmentedPacket(udpp);

									// if the fragment is for a new datagram, add it to the fPackets
									//   ArrayList
									if (datagramIndex == -1) {
										fp = new FragmentedPacket();
										fPackets.add(fp);
									}
									else {
										fp = fPackets.get(datagramIndex);
									}
									System.out.println("");

									// add this fragment to the datagram
									boolean completed = fp.addFragment(udpp);

									if (completed) {
										// create and print out descriptor (triple)
										PacketDescriptor pd = new PacketDescriptor(fp);
										pd.printDescriptor();
										parsePacket(fp.contructCompletedPacket(), 
												-1, argH, printWriter, sRules);
									}
								}
								else {
									SnortRule.checkRules(udpp, sRules);
								}
								parsed = true;
							}
						}
						else if (!argH.get("dAdd").equals("-1")) {
							if (udpp.getDstIPdottedString().equals(argH.get("dAdd"))) {
								totalParseS += udpp.EthPrettyParse(packetNum)+"\n";
								totalParseS += udpp.IPprettyParse();
								totalParseS += udpp.UDPprettyParse();

								// if this is a IP-fragmented UDP packet
								if (udpp.isFragment()) {
									FragmentedPacket fp;
									int datagramIndex = indexOfFragmentedPacket(udpp);

									// if the fragment is for a new datagram, add it to the fPackets
									//   ArrayList
									if (datagramIndex == -1) {
										fp = new FragmentedPacket();
										fPackets.add(fp);
									}
									else {
										fp = fPackets.get(datagramIndex);
									}
									System.out.println("");

									// add this fragment to the datagram
									boolean completed = fp.addFragment(udpp);

									if (completed) {
										// create and print out descriptor (triple)
										PacketDescriptor pd = new PacketDescriptor(fp);
										pd.printDescriptor();
										parsePacket(fp.contructCompletedPacket(), 
												-1, argH, printWriter, sRules);
									}
								}
								else {
									SnortRule.checkRules(udpp, sRules);
								}
								parsed = true;
							}
						}
						// no src or dst address is specified
						else {
							totalParseS += udpp.EthPrettyParse(packetNum)+"\n";
							totalParseS += udpp.IPprettyParse();
							totalParseS += udpp.UDPprettyParse();

							// if this is a IP-fragmented UDP packet
							if (udpp.isFragment()) {
								FragmentedPacket fp;
								int datagramIndex = indexOfFragmentedPacket(udpp);

								// if the fragment is for a new datagram, add it to the fPackets
								//   ArrayList
								if (datagramIndex == -1) {
									fp = new FragmentedPacket();
									fPackets.add(fp);
								}
								else {
									fp = fPackets.get(datagramIndex);
								}
								System.out.println("");

								// add this fragment to the datagram
								boolean completed = fp.addFragment(udpp);

								if (completed) {
									// create and print out descriptor (triple)
									PacketDescriptor pd = new PacketDescriptor(fp);
									pd.printDescriptor();
									parsePacket(fp.contructCompletedPacket(), 
											-1, argH, printWriter, sRules);
								}
							}
							else {
								SnortRule.checkRules(udpp, sRules);
							}
							parsed = true;
						}
					}
					else {
						totalParseS += "IP checksum incorrect\n";
					}
				}
			}
			//
			// ICMP
			////////////////////////////////////////////////////////////////////////////////////////
			else if (type.equals("icmp")) {
				// check cmd line "-type" argument
				if (((argH.get("type").toLowerCase()).equals("-1")) 
						|| ((argH.get("type").toLowerCase()).equals("icmp"))
						|| ((argH.get("type").toLowerCase()).equals("ip"))
						|| ((argH.get("type")).toLowerCase().equals("eth"))) {
					icmpp = new ICMPPacket(packet);
					totalParseS += icmpp.parseICMP();	

					// verify IP checksum
					if (icmpp.checkChecksum()) {

						// check src and dst address arguments
						if (argH.get("sord").equals("1")) {
							if (icmpp.getSrcIPdottedString().equals(argH.get("sAdd"))
									|| icmpp.getDstIPdottedString().equals(argH.get("dAdd"))) {
								totalParseS += icmpp.EthPrettyParse(packetNum)+"\n";
								totalParseS += icmpp.IPprettyParse();
								totalParseS += icmpp.ICMPprettyParse();

								// if this is a IP-fragmented ICMP packet
								if (icmpp.isFragment()) {
									FragmentedPacket fp;
									int datagramIndex = indexOfFragmentedPacket(icmpp);

									// if the fragment is for a new datagram, add it to the fPackets
									//   ArrayList
									if (datagramIndex == -1) {
										fp = new FragmentedPacket();
										fPackets.add(fp);
									}
									else {
										fp = fPackets.get(datagramIndex);
									}
									System.out.println("");

									// add this fragment to the datagram
									boolean completed = fp.addFragment(icmpp);

									if (completed) {
										// create and print out descriptor (triple)
										PacketDescriptor pd = new PacketDescriptor(fp);
										pd.printDescriptor();
										parsePacket(fp.contructCompletedPacket(), 
												-1, argH, printWriter, sRules);
									}
								}
								else {
									SnortRule.checkRules(icmpp, sRules);
								}
								parsed = true;
							}
						}
						else if (argH.get("sandd").equals("1")) {
							if (icmpp.getSrcIPdottedString().equals(argH.get("sAdd"))
									&& icmpp.getDstIPdottedString().equals(argH.get("dAdd"))) {
								totalParseS += icmpp.EthPrettyParse(packetNum)+"\n";
								totalParseS += icmpp.IPprettyParse();
								totalParseS += icmpp.ICMPprettyParse();

								// if this is a IP-fragmented ICMP packet
								if (icmpp.isFragment()) {
									FragmentedPacket fp;
									int datagramIndex = indexOfFragmentedPacket(icmpp);

									// if the fragment is for a new datagram, add it to the fPackets
									//   ArrayList
									if (datagramIndex == -1) {
										fp = new FragmentedPacket();
										fPackets.add(fp);
									}
									else {
										fp = fPackets.get(datagramIndex);
									}
									System.out.println("");

									// add this fragment to the datagram
									boolean completed = fp.addFragment(icmpp);

									if (completed) {
										// create and print out descriptor (triple)
										PacketDescriptor pd = new PacketDescriptor(fp);
										pd.printDescriptor();
										parsePacket(fp.contructCompletedPacket(), 
												-1, argH, printWriter, sRules);
									}
								}
								else {
									SnortRule.checkRules(icmpp, sRules);
								}
								parsed = true;
							}
						}
						else if (!argH.get("sAdd").equals("-1")) {
							if (icmpp.getSrcIPdottedString().equals(argH.get("sAdd"))) {
								totalParseS += icmpp.EthPrettyParse(packetNum)+"\n";
								totalParseS += icmpp.IPprettyParse();
								totalParseS += icmpp.ICMPprettyParse();

								// if this is a IP-fragmented ICMP packet
								if (icmpp.isFragment()) {
									FragmentedPacket fp;
									int datagramIndex = indexOfFragmentedPacket(icmpp);

									// if the fragment is for a new datagram, add it to the fPackets
									//   ArrayList
									if (datagramIndex == -1) {
										fp = new FragmentedPacket();
										fPackets.add(fp);
									}
									else {
										fp = fPackets.get(datagramIndex);
									}
									System.out.println("");

									// add this fragment to the datagram
									boolean completed = fp.addFragment(icmpp);

									if (completed) {
										// create and print out descriptor (triple)
										PacketDescriptor pd = new PacketDescriptor(fp);
										pd.printDescriptor();
										parsePacket(fp.contructCompletedPacket(), 
												-1, argH, printWriter, sRules);
									}
								}
								else {
									SnortRule.checkRules(icmpp, sRules);
								}
								parsed = true;
							}
						}
						else if (!argH.get("dAdd").equals("-1")) {
							if (icmpp.getDstIPdottedString().equals(argH.get("dAdd"))) {
								totalParseS += icmpp.EthPrettyParse(packetNum)+"\n";
								totalParseS += icmpp.IPprettyParse();
								totalParseS += icmpp.ICMPprettyParse();

								// if this is a IP-fragmented ICMP packet
								if (icmpp.isFragment()) {
									FragmentedPacket fp;
									int datagramIndex = indexOfFragmentedPacket(icmpp);

									// if the fragment is for a new datagram, add it to the fPackets
									//   ArrayList
									if (datagramIndex == -1) {
										fp = new FragmentedPacket();
										fPackets.add(fp);
									}
									else {
										fp = fPackets.get(datagramIndex);
									}
									System.out.println("");

									// add this fragment to the datagram
									boolean completed = fp.addFragment(icmpp);

									if (completed) {
										// create and print out descriptor (triple)
										PacketDescriptor pd = new PacketDescriptor(fp);
										pd.printDescriptor();
										parsePacket(fp.contructCompletedPacket(), 
												-1, argH, printWriter, sRules);
									}
								}
								else {
									SnortRule.checkRules(icmpp, sRules);
								}
								parsed = true;
							}
						}
						// no src or dst address is specified
						else {
							totalParseS += icmpp.EthPrettyParse(packetNum)+"\n";
							totalParseS += icmpp.IPprettyParse();
							totalParseS += icmpp.ICMPprettyParse();

							// if this is a IP-fragmented ICMP packet
							if (icmpp.isFragment()) {
								FragmentedPacket fp;
								int datagramIndex = indexOfFragmentedPacket(icmpp);

								// if the fragment is for a new datagram, add it to the fPackets
								//   ArrayList
								if (datagramIndex == -1) {
									fp = new FragmentedPacket();
									fPackets.add(fp);
								}
								else {
									fp = fPackets.get(datagramIndex);
								}
								System.out.println("");

								// add this fragment to the datagram
								boolean completed = fp.addFragment(icmpp);

								if (completed) {
									// create and print out descriptor (triple)
									PacketDescriptor pd = new PacketDescriptor(fp);
									pd.printDescriptor();
									parsePacket(fp.contructCompletedPacket(), 
											-1, argH, printWriter, sRules);
								}
							}
							else {
								SnortRule.checkRules(icmpp, sRules);
							}
							parsed = true;
						}
					}
					else {
						totalParseS += "IP checksum incorrect\n";
					}

				}
			}

			//
			// assume other packets are IP and Ethernet
			////////////////////////////////////////////////////////////////////////////////////////
			else {
				// check cmd line type argument
				if (((argH.get("type").toLowerCase()).equals("-1")) 
						|| ((argH.get("type").toLowerCase()).equals("ip"))
						|| ((argH.get("type")).toLowerCase().equals("eth"))) {
					ipp = new IPPacket(packet);
					totalParseS += ipp.parseIP()+"\n";

					// verify IP checksum
					if (ipp.checkChecksum()) {

						// check src and dst address arguments
						if (argH.get("sord").equals("1")) {
							if (ipp.getSrcIPdottedString().equals(argH.get("sAdd"))
									|| ipp.getDstIPdottedString().equals(argH.get("dAdd"))) {
								totalParseS += ipp.EthPrettyParse(packetNum)+"\n";
								totalParseS += ipp.IPprettyParse();

								// if this is a IP-fragmented packet
								if (ipp.isFragment()) {
									FragmentedPacket fp;
									int datagramIndex = indexOfFragmentedPacket(ipp);

									// if the fragment is for a new datagram, add it to the fPackets
									//   ArrayList
									if (datagramIndex == -1) {
										fp = new FragmentedPacket();
										fPackets.add(fp);
									}
									else {
										fp = fPackets.get(datagramIndex);
									}
									System.out.println("");

									// add this fragment to the datagram
									boolean completed = fp.addFragment(ipp);

									if (completed) {
										// create and print out descriptor (triple)
										PacketDescriptor pd = new PacketDescriptor(fp);
										pd.printDescriptor();
										parsePacket(fp.contructCompletedPacket(), 
												-1, argH, printWriter, sRules);
									}
								}
								else {
									SnortRule.checkRules(ipp, sRules);
								}
								parsed = true;
							}
						}
						else if (argH.get("sandd").equals("1")) {
							if (ipp.getSrcIPdottedString().equals(argH.get("sAdd"))
									&& ipp.getDstIPdottedString().equals(argH.get("dAdd"))) {
								totalParseS += ipp.EthPrettyParse(packetNum)+"\n";
								totalParseS += ipp.IPprettyParse();

								// if this is a IP-fragmented packet
								if (ipp.isFragment()) {
									FragmentedPacket fp;
									int datagramIndex = indexOfFragmentedPacket(ipp);

									// if the fragment is for a new datagram, add it to the fPackets
									//   ArrayList
									if (datagramIndex == -1) {
										fp = new FragmentedPacket();
										fPackets.add(fp);
									}
									else {
										fp = fPackets.get(datagramIndex);
									}
									System.out.println("");

									// add this fragment to the datagram
									boolean completed = fp.addFragment(ipp);

									if (completed) {
										// create and print out descriptor (triple)
										PacketDescriptor pd = new PacketDescriptor(fp);
										pd.printDescriptor();
										parsePacket(fp.contructCompletedPacket(), 
												-1, argH, printWriter, sRules);
									}
								}
								else {
									SnortRule.checkRules(ipp, sRules);
								}
								parsed = true;
							}
						}
						else if (!argH.get("sAdd").equals("-1")) {
							if (ipp.getSrcIPdottedString().equals(argH.get("sAdd"))) {
								totalParseS += ipp.EthPrettyParse(packetNum)+"\n";
								totalParseS += ipp.IPprettyParse();

								// if this is a IP-fragmented packet
								if (ipp.isFragment()) {
									FragmentedPacket fp;
									int datagramIndex = indexOfFragmentedPacket(ipp);

									// if the fragment is for a new datagram, add it to the fPackets
									//   ArrayList
									if (datagramIndex == -1) {
										fp = new FragmentedPacket();
										fPackets.add(fp);
									}
									else {
										fp = fPackets.get(datagramIndex);
									}
									System.out.println("");

									// add this fragment to the datagram
									boolean completed = fp.addFragment(ipp);

									if (completed) {
										// create and print out descriptor (triple)
										PacketDescriptor pd = new PacketDescriptor(fp);
										pd.printDescriptor();
										parsePacket(fp.contructCompletedPacket(), 
												-1, argH, printWriter, sRules);
									}
								}
								else {
									SnortRule.checkRules(ipp, sRules);
								}
								parsed = true;
							}
						}
						else if (!argH.get("dAdd").equals("-1")) {
							if (ipp.getDstIPdottedString().equals(argH.get("dAdd"))) {
								totalParseS += ipp.EthPrettyParse(packetNum)+"\n";
								totalParseS += ipp.IPprettyParse();

								// if this is a IP-fragmented packet
								if (ipp.isFragment()) {
									FragmentedPacket fp;
									int datagramIndex = indexOfFragmentedPacket(ipp);

									// if the fragment is for a new datagram, add it to the fPackets
									//   ArrayList
									if (datagramIndex == -1) {
										fp = new FragmentedPacket();
										fPackets.add(fp);
									}
									else {
										fp = fPackets.get(datagramIndex);
									}
									System.out.println("");

									// add this fragment to the datagram
									boolean completed = fp.addFragment(ipp);

									if (completed) {
										// create and print out descriptor (triple)
										PacketDescriptor pd = new PacketDescriptor(fp);
										pd.printDescriptor();
										parsePacket(fp.contructCompletedPacket(), 
												-1, argH, printWriter, sRules);
									}
								}
								else {
									SnortRule.checkRules(ipp, sRules);
								}
								parsed = true;
							}
						}
						// no src or dst address is specified
						else {
							totalParseS += ipp.EthPrettyParse(packetNum)+"\n";
							totalParseS += ipp.IPprettyParse();

							// if this is a IP-fragmented packet
							if (ipp.isFragment()) {
								FragmentedPacket fp;
								int datagramIndex = indexOfFragmentedPacket(ipp);

								// if the fragment is for a new datagram, add it to the fPackets
								//   ArrayList
								if (datagramIndex == -1) {
									fp = new FragmentedPacket();
									fPackets.add(fp);
								}
								else {
									fp = fPackets.get(datagramIndex);
								}
								System.out.println("");

								// add this fragment to the datagram
								boolean completed = fp.addFragment(ipp);

								if (completed) {
									// create and print out descriptor (triple)
									PacketDescriptor pd = new PacketDescriptor(fp);
									pd.printDescriptor();
									parsePacket(fp.contructCompletedPacket(), 
											-1, argH, printWriter, sRules);
								}
							}
							else {
								SnortRule.checkRules(ipp, sRules);
							}
							parsed = true;
						}
					}
					else {
						totalParseS += "IP checksum incorrect\n";
					}
				}
			}
		}
		// if the "-h" (headers only) option us specified, remove the payloads
		if (argH.get("headers").equals("1")) {
			totalParseS = totalParseS.replaceAll("(?s)ethPayload:.*IP\n", "\nIP\n");
			totalParseS = totalParseS.replaceAll("(?s)IPpayload:.*TCP\n", "\nTCP\n");
			totalParseS = totalParseS.replaceAll("(?s)IPpayload:.*UDP\n", "\nUDP\n");
			totalParseS = totalParseS.replaceAll("(?s)IPpayload:.*ICMP\n", "\nICMP\n");
			totalParseS = totalParseS.replaceAll("(?s)UDPpayload:.*\\z", "");
			totalParseS = totalParseS.replaceAll("(?s)TCPpayload:.*\\z", "");
			totalParseS = totalParseS.replaceAll("(?s)ICMPpayload:.*\\z", "");
		}

		// print to the output file if that option is specified
		if (argH.get("outfile").equals("-1")) {
			System.out.print(totalParseS);
		}
		else {
			printWriter.print(totalParseS);
		}

		return parsed;
	}

	private static String connectToAdapter(SimplePacketDriver driver, int adapterNum) {
		String outputS = "";

		//Get adapter names and print info
		String[] adapters=driver.getAdapterNames();
		//System.out.println("Number of adapters: "+adapters.length);
		for (int i=0; i< adapters.length; i++) {
			//System.out.println("Device name in Java ="+adapters[i]);
		}

		//Open first found adapter (usually first Ethernet card found)
		if (driver.openAdapter(adapters[adapterNum])) {
			outputS += "Adapter is open: "+adapters[adapterNum];
		}
		return outputS;
	}

	private static BufferedReader openFile(String filename) {
		BufferedReader br = null;
		try {
			File f = new File(filename);
			br = new BufferedReader(new FileReader(f));
		} catch (Exception e) {
			System.out.println("Unable to open input file "+filename+".");
			System.exit(1);
		}
		return br;
	}

	// read a specified number of packets from a file; pass -1 to num to read until the 
	//   end of the file 
	private static ArrayList<byte[]> readPackets(BufferedReader br, int num) 
	{
		ArrayList<byte[]> packets = new ArrayList<>();
		byte[] packet;

		if (num==-1) {
			// read until end of file
			while (true) {
				packet = readPacket(br);
				if (packet==null) {
					break;
				}
				else {
					packets.add(packet);
				}
			}
		}
		else {
			// read num packets or until end of file
			for (int i=0; i<num; i++) {
				packet = readPacket(br);
				if (packet==null) {
					break;
				}
				else {
					packets.add(packet);
				}
			}
		}

		return packets;
	}

	// read a single packet from a BufferedReader
	private static byte[] readPacket(BufferedReader br) {
		byte[] packet = null;
		int temp;
		String packetS = "";
		try {
			while(true) {
				temp = br.read();
				// catch EOF
				if (temp==-1) {
					break;
				}
				// catch CR and new line
				else if (temp==13) {
					temp = br.read();
					temp = br.read();
					if (temp==13) {
						break;
					}
				}
				else if (temp==10) {
					// skip this char (new line)
				}
				// valid character
				else {
					packetS += (char)temp;
				}
			}
		}
		catch (Exception e) {
			System.out.println("Unable to read from input file.");
			System.exit(1);
		}

		// an empty packetS indicates EOF
		if (!(packetS.equals(""))) {
			packet = packetStringToSignedBytes(packetS);
		}
		return packet;
	}

	// read a specified number of packets using a SimplePacketDriver (blocking operation)
	private static ArrayList<byte[]> readPackets(SimplePacketDriver driver, int num) {
		ArrayList<byte[]> packets = new ArrayList<byte[]>();
		byte[] packet;
		for (int i=0; i<num; i++) {
			packet=driver.readPacket();
			//Wrap it into a ByteBuffer
			//ByteBuffer Packet=ByteBuffer.wrap(packet);
			packets.add(packet);
			//Print packet summary
			//ps.println("Packet: "+Packet+" with capacity: "+Packet.capacity());
		}
		return packets;
	}

	private static byte[] packetStringToSignedBytes(String packetS) {
		packetS.trim();
		String[] packetSA =	packetS.split(" ");

		byte[] packet = new byte[packetSA.length];
		int tempI = 0;
		// convert from 2-char string array to byte array
		for (int i=0; i<packetSA.length; i++) {
			tempI = Integer.parseUnsignedInt(packetSA[i], 16);
			packet[i] = (byte) tempI;
		}
		return packet;
	}

	// a return value of -1 indicates that no fragment for this IP identification number has been 
	//   received
	private static int indexOfFragmentedPacket(IPPacket ipp) {
		for (int i=0; i<fPackets.size(); i++) {
			if (ipp.getIdentificationI() == fPackets.get(i).getIPid()) {
				return i;
			}
		}
		return -1;
	}

	private static String getSubsetString(byte[] bytes, int lowerIndex, int upperIndex) {
		String subset = "";

		// convert each byte into a hex string and add it to the subset string
		for (int i=lowerIndex; i<upperIndex; i++) {
			if (i==(upperIndex-1)) {
				subset = subset + driver.byteToHex(bytes[i]);
			}
			else {
				subset = subset + driver.byteToHex(bytes[i]) + " ";
			}
		}

		return subset;
	}

	private static void tester() {
		LinkedList<String> rules = SnortRule.readRules("rules.txt");

		int rulesLen = rules.size();

		SnortRule sr;

		for (int i=0; i<rulesLen; i++) {

			System.out.println("\nrule: "+rules.get(0));

			sr = new SnortRule(rules.pop());
			System.out.println();
			System.out.println("rule: "+sr.getRuleStr());
			System.out.println("action: "+sr.isAction());
			System.out.println("protocol: "+sr.getProtocol());
			System.out.println("srcIP: "+sr.getSrcIP());
			System.out.println("srcMask: "+sr.getSrcMask());
			System.out.println("srcPort1: "+sr.getSrcPort1());
			System.out.println("srcPort2: "+sr.getSrcPort2());

			System.out.println("direction: "+sr.isDirection());

			System.out.println("dstIP: "+sr.getDstIP());
			System.out.println("dstMask: "+sr.getDstMask());
			System.out.println("dstPort1: "+sr.getDstPort1());
			System.out.println("dstPort2: "+sr.getDstPort2());

			// snort rule options
			System.out.println("msgO: "+sr.getMsgO());
			System.out.println("logtoO: "+sr.getLogtoO());
			System.out.println("ttlO: "+sr.getTtlO());
			System.out.println("tosO: "+sr.getTosO());
			System.out.println("idO: "+sr.getIdO());
			System.out.println("fragoffsetO: "+sr.getFragoffsetO());
			System.out.println("ipoptsO: "+sr.getipoptsO());
			System.out.println("fragbitsModO: "+sr.getFragbitsModO());
			System.out.println("fragbitsBitsO: "+sr.getFragbitsBitsO());
			System.out.println("dsizeMinO: "+sr.getDsizeMinO());
			System.out.println("dsizeMaxO: "+sr.getDsizeMaxO());
			System.out.println("flagsModO: "+sr.getFlagsModO());
			System.out.println("flagsBitsO: "+sr.getFlagsBitsO());
			System.out.println("seqO: "+sr.getSeqO());
			System.out.println("ackO: "+sr.getAckO());
			System.out.println("itypeO: "+sr.getItypeO());
			System.out.println("icodeO: "+sr.getIcodeO());
			System.out.println("contentNotO: "+sr.iscontentNotO());
			System.out.println("contentO: "+sr.getContentO());
			System.out.println("sameIPo: "+sr.isSameIPo());
			System.out.println("sid0: "+sr.getSid0());

		}

		System.exit(1);
	}
}

