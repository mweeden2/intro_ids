import java.util.ArrayList;

public class PacketDescriptor {

	private int segmentID;
	private Packet fullPacket;
	private ArrayList<IPPacket> fragments;

	public PacketDescriptor(FragmentedPacket fp) {
		segmentID = fp.getSid();
		fragments = fp.getFragments();
		// only report first fragment if the datagram was too large or timed out
		if (segmentID == 3 || segmentID == 4) {
			fullPacket = fragments.get(0);
		}
		else {
			fullPacket = new IPPacket(fp.contructCompletedPacket());
		}
	}

	public PacketDescriptor(ARPPacket arpp) {
		segmentID = 0;
		fullPacket = arpp;
		fragments = null;
	}

	public void printDescriptor () {
		SimplePacketDriver driver = new SimplePacketDriver();

		System.out.println("*********************************************************************");
		System.out.println("                              Packet Descriptor");
		System.out.println("*********************************************************************");
		
		System.out.println("sid: " + segmentID);
		System.out.println("\nfull packet:\n"+
				driver.byteArrayToString(fullPacket.getBytes()));
		System.out.println("fragments:");
		
		if (fragments == null) {
			System.out.println(driver.byteArrayToString(fullPacket.getBytes()));
		}
		else if (fragments.size() > 0) {
			for (int i=0; i<fragments.size(); i++) {
				System.out.println("fragment "+i+":\n"+
						driver.byteArrayToString
						(fragments.get(i).getBytes()));
			}
		}
		else {
			System.out.println("There are no saved fragments for this packet.");
		}
	}

	public int getSegmentID() {
		return segmentID;
	}
	public void setSegmentID(int segmentID) {
		this.segmentID = segmentID;
	}
	public Packet getFullPacket() {
		return fullPacket;
	}
	public void setFullPacket(Packet fullPacket) {
		this.fullPacket = fullPacket;
	}
	public ArrayList<IPPacket> getFragments() {
		return fragments;
	}
	public void setFragments(ArrayList<IPPacket> fragments) {
		this.fragments = fragments;
	}	
}
