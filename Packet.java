import java.util.Arrays;

/*
 * Packet
 * 2/3/16 - 3/15/16
 * 
 * by Matt Weeden
 * 
 * CS 7473 Network Security
 * Dr. Mauricio Papa
 * 
 */

public class Packet {

	private byte[] bytes;

	private int packetLengthInBytes;

	private SimplePacketDriver driver;

	/////////////////////////////////////////////////////////////////////////////////////////////////
	public Packet(byte[] bs) {
		bytes = bs;
		packetLengthInBytes = bs.length;
		driver = new SimplePacketDriver();
	}

	// assume all packets are Ethernet
	public static String packetCharacterizer(byte[] packet) {
		SimplePacketDriver driver = new SimplePacketDriver();
		String packetType = "";

		byte[] etherType = Arrays.copyOfRange(packet, 12, 14);
		String etherTypeString = driver.byteArrayToString(etherType).substring(0, 5);

		if (etherTypeString.equals("08 06")) {
			packetType = "arp";
		}
		else if (etherTypeString.equals("08 00")) {			
			byte[] IPprotocol = new byte[1];
			IPprotocol[0] = packet[9+14];
			String IPprotocolString = driver.byteArrayToString(IPprotocol).substring(0, 2);

			if (IPprotocolString.equals("01") ) {
				packetType = "icmp";
			}
			else if (IPprotocolString.equals("06")) {
				packetType = "tcp";
			}
			else if (IPprotocolString.equals("11")) {
				packetType = "udp";
			}
		}
		return packetType;
	}

	public void printRawPacket() {
		System.out.println(driver.byteArrayToString(bytes));
	}

	public boolean isSet(byte b, int index) {
		return (b & (1 << index)) != 0;
	}

	public boolean isSet(String hex, int index) {
		int tempI = Integer.parseUnsignedInt(hex, 16);
		return (((byte) tempI) & (1 << index)) != 0;
	}

	public boolean isSetPacket(Integer packetByteIndex, int index) {
		return (bytes[packetByteIndex] & (1 << index)) != 0;
	}

	public byte[] getBytes() {
		return bytes;
	}

	public void setBytes(byte[] theseBytes) {
		bytes = theseBytes;
	}

	public int getPacketLengthInBytes() {
		return packetLengthInBytes;
	}

	public void setPacketLengthInBytes(int PacketLengthInBytes) {
		packetLengthInBytes = PacketLengthInBytes;
	}

	public SimplePacketDriver getDriver() {
		return driver;
	}

	public void setDriver(SimplePacketDriver Driver) {
		driver = Driver;
	}
}
