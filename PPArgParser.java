/*
 * PacketParser Arg Parser
 * 2/3/16 - 3/15/16
 * 
 * by Matt Weeden
 * 
 * CS 7473 Network Security
 * Dr. Mauricio Papa
 * 
 */

import java.util.HashMap;

public class PPArgParser {

	private static String usageNote = "Usage:\n"
			+ "-c count\t\t\tExit after receiving count packets\n"
			+ "-r filename\t\t\tRead packets from file (the program will "
			+ "read packets from the network by default)\n"
			+ "-o filename\t\t\tSave output to filename\n"
			+ "-t type\t\t\t\tPrint only packets of the specified type where "
			+ "type is one of: eth, arp, ip, icmp, tcp or udp\n"
			+ "-h\t\t\t\tPrint header info only as specified by -t\n"
			+ "-src saddress\t\t\tPrint only packets with source IP address "
			+ "equal to saddress (use dot notation)\n"
			+ "-dst daddress\t\t\tPrint only packets with destination IP address "
			+ "equal to daddress (use dot notation)\n"
			+ "-sord saddress daddress\t\tPrint only packets where the "
			+ "source address matches saddress or the destination address "
			+ "matches daddress\n"
			+ "-sandd saddress daddress\tPrint only packets where the "
			+ "source address matches saddress and the destination "
			+ "address matches daddress\n"
			+ "-sport port1 port2\t\tPrint only packets where the source "
			+ "port is in the range port1-port2\n"
			+ "-dport port1 port2\t\tPrint only packets where the "
			+ "destination port is in the range port1-port2\n"
			+ "-anum adapternum\t\tUse the specified network adapter number "
			+ "(0..#ofNetworkAdapters)";

	private static HashMap<String, String> aHashMap;

	private static void initHash() {
		aHashMap = new HashMap<String, String>(1);

		// "0" values are used as FALSE for boolean key values
		// "-1" values are used as NULL for string or int key values
		aHashMap.put("count", "-1");
		aHashMap.put("infile", "-1");
		aHashMap.put("outfile", "-1");
		aHashMap.put("type", "-1");
		aHashMap.put("headers", "0");
		aHashMap.put("sAdd", "-1");
		aHashMap.put("dAdd", "-1");
		aHashMap.put("sord", "0");
		aHashMap.put("sandd", "0");
		// default port range is complete possible range for port numbers
		aHashMap.put("sPortRangeLower", "0");
		aHashMap.put("sPortRangeUpper", "65535");
		aHashMap.put("dPortRangeLower", "0");
		aHashMap.put("dPortRangeUpper", "65535");
		// adapter 0 is the default adapter number
		aHashMap.put("adapter", "0");
	}

	public static HashMap<String, String> parse(String arguments[]) {
		initHash();
		
		try {
			if (arguments.length > 0) {
				if (arguments.length == 1) {
					System.out.println(usageNote);
				}
				// NOTE: each case checks if its associated value has already been updated
				for (int i=0; i<arguments.length; i++) {
					if (arguments[i].equals("-c")) {
						int temp = Integer.parseInt(arguments[i+1]);
						if (temp<0 || !aHashMap.get("count").equals("-1")) {
							System.out.println(usageNote);
							System.exit(1);
						}
						aHashMap.put("count", arguments[i+1]);
					}

					else if (arguments[i].equals("-r")) {
						if (!aHashMap.get("infile").equals("-1")) {
							System.out.println(usageNote);
							System.exit(1);
						}
						aHashMap.put("infile", arguments[i+1]);
					}

					else if (arguments[i].equals("-o")) {
						if (!aHashMap.get("outfile").equals("-1")) {
							System.out.println(usageNote);
							System.exit(1);
						}
						aHashMap.put("outfile", arguments[i+1]);
					}

					else if (arguments[i].equals("-t")) {
						if (aHashMap.get("type").equals("-1") &&
								(arguments[i+1].toLowerCase().equals("eth")
								|| arguments[i+1].toLowerCase().equals("arp")
								|| arguments[i+1].toLowerCase().equals("ip")
								|| arguments[i+1].toLowerCase().equals("tcp")
								|| arguments[i+1].toLowerCase().equals("udp")
								|| arguments[i+1].toLowerCase().equals("icmp"))) {
							aHashMap.put("type", arguments[i+1]);
						}
						else {							
							System.out.println(usageNote);
							System.exit(1);
						}
					}

					else if (arguments[i].equals("-h")) {
						aHashMap.put("headers", "1");
					}

					else if (arguments[i].equals("-src")) {
						if (!aHashMap.get("sAdd").equals("-1")) {
							System.out.println(usageNote);
							System.exit(1);
						}
						aHashMap.put("sAdd", arguments[i+1]);
					}

					else if (arguments[i].equals("-dst")) {
						if (!aHashMap.get("dAdd").equals("-1")) {
							System.out.println(usageNote);
							System.exit(1);
						}
						aHashMap.put("dAdd", arguments[i+1]);
					}

					else if (arguments[i].equals("-sord")) {
						if (!aHashMap.get("sAdd").equals("-1") || 
								!aHashMap.get("dAdd").equals("-1") ||
								aHashMap.get("sord").equals("1")) {
							System.out.println(usageNote);
							System.exit(1);
						}
						aHashMap.put("sord", "1");
						aHashMap.put("sAdd", arguments[i+1]);
						aHashMap.put("dAdd", arguments[i+2]);
					}

					else if (arguments[i].equals("-sandd")) {
						if (!aHashMap.get("sAdd").equals("-1") || 
								!aHashMap.get("dAdd").equals("-1") ||
								aHashMap.get("sandd").equals("1")) {
							System.out.println(usageNote);
							System.exit(1);
						}
						aHashMap.put("sandd", "1"); 	
						aHashMap.put("sAdd", arguments[i+1]);
						aHashMap.put("dAdd", arguments[i+2]);
					}

					else if (arguments[i].equals("-sport")) {
						if (!aHashMap.get("sPortRangeLower").equals("0") ||
								!aHashMap.get("sPortRangeUpper").equals("65535")) {
							System.out.println(usageNote);
							System.exit(1);
						}
						int temp = Integer.parseInt(arguments[i+1]);
						int temp2 = Integer.parseInt(arguments[i+1]);
						if (temp<0 || temp2>65535 || temp>temp2) {
							System.out.println(usageNote);
							System.exit(1);
						}
						aHashMap.put("sPortRangeLower", arguments[i+1]);
						aHashMap.put("sPortRangeUpper", arguments[i+2]);
					}

					else if (arguments[i].equals("-dport")) {
						if (!aHashMap.get("dPortRangeLower").equals("0") ||
								!aHashMap.get("dPortRangeUpper").equals("65535")) {
							System.out.println(usageNote);
							System.exit(1);
						}
						int temp = Integer.parseInt(arguments[i+1]);
						int temp2 = Integer.parseInt(arguments[i+1]);
						if (temp<0 || temp2>65535 || temp>temp2) {
							System.out.println(usageNote);
							System.exit(1);
						}
						aHashMap.put("dPortRangeLower", arguments[i+1]);
						aHashMap.put("dPortRangeUpper", arguments[i+2]);
					}

					else if (arguments[i].equals("-anum")) {
						int temp = Integer.parseInt(arguments[i+1]);
						if (temp<0) {
							System.out.println(usageNote);
							System.exit(1);
						}
						aHashMap.put("adapter", arguments[i+1]);
					}
					
					// catch if an unknown or misspelled option is used
					else if (arguments[i].startsWith("-")) {
						System.out.println(usageNote);
						System.exit(1);
					}
				}
			}
		} catch (Exception e) {
			System.out.println(usageNote);
			System.exit(1);
		}
		
		// check if usage is correct
		
		// if both "-src" and "-dst" is used, but not "-sord" or "-sandd"
		if (!aHashMap.get("sAdd").equals("-1") && 
				!aHashMap.get("dAdd").equals("-1") &&
				aHashMap.get("sord").equals("0") &&
				aHashMap.get("sandd").equals("0")) {
			System.out.println(usageNote);
			System.exit(1);
		}
		
		// if "-h" is set, but "-t" is not specified
		else if (aHashMap.get("headers").equals("1") &&
				aHashMap.get("type").equals("-1")) {
			System.out.println(usageNote);
			System.exit(1);
		}
		
		return aHashMap;
	}

}
