/*
 * Fragmented Packet
 * 3/16/16 - //16
 * 
 * by Matt Weeden
 * 
 * CS 7473 Network Security
 * Dr. Mauricio Papa
 * 
 */

import java.util.ArrayList;

public class FragmentedPacket {

	// an sid of -1 indicates an unfinished reassembly
	private int sid;
	private String srcIPaddS;
	private String dstIPaddS;
	private String IPprotocolS;
	private int IPid;
	private ArrayList<Byte> totalDataBuffer;
	private int datagramLength;
	private IPPacket totalIPp;
	private ArrayList<IPPacket> fragments;
	private ArrayList<Hole> holes;

	private long timeoutTime;	
	private boolean dropped;

	// construct an empty FragmentedPacket
	public FragmentedPacket() {
		sid=-1;
		IPid=-1;
		totalIPp=null;

		// initialize data buffer with all 0 bytes
		totalDataBuffer = new ArrayList<Byte>(65515);
		for (int i = 0; i < 65515; i++) {
			totalDataBuffer.add((byte) -128);
		}

		totalIPp=null;
		fragments=new ArrayList<IPPacket>();
		holes = new ArrayList<Hole>();
		holes.add(new Hole());
		dropped = false;
	}

	// ** NOTE: this methods overrides previously-stored fragment data ** //
	public boolean addFragment(IPPacket ipp) {
		boolean completed = false;

		// update and src/dst IP address, IP protocol, and IP id if this is the first fragment
		if (IPid == -1) {
			srcIPaddS = ipp.getSrcIPstring();
			dstIPaddS = ipp.getDstIPstring();
			IPprotocolS = ipp.getProtocolString();
			IPid = ipp.getIdentificationI();
			sid = 1;

			// set the timeout time to 4 seconds in the future
			timeoutTime = System.currentTimeMillis() + 10000;
		}

		// make sure this IPPacket belongs to this datagram and that it has not timed out or been 
		//   dropped
		else if (ipp.getIdentificationI() != IPid || 
				(!(ipp.getSrcIPstring().equals(srcIPaddS))) ||
				(!(ipp.getDstIPstring().equals(dstIPaddS))) ||
				(!(ipp.getProtocolString().equals(IPprotocolS))) ||
				(dropped == true)) {

			System.out.println("This fragment does not belong to this datagram or the datagram "+
					"has been dropped.");
			return false;
		}
		
		
		if (timeoutTime <= System.currentTimeMillis()) {
			System.out.println("This datagram has timed out.");
			sid = 4;
			// return true so that a PacketDescriptor is made
			return true;
		}


		fragments.add(ipp);

		// make sure the length of the datagram is not >64K
		if ((sid == 3) || (ipp.getFragmentOffsetI() + ipp.getIPpayloadLengthI()) >= 64000) {
			sid = 3;
		}

		// update last hole length if this is the "no more fragments" packet
		if (!ipp.isMoreFragments()) {	
			datagramLength = ipp.getFragmentOffsetI() + ipp.getIPpayloadLengthI();
			for (int i=0; i<holes.size(); i++) {
				// find the last hole
				if (holes.get(i).getLast() == 65535) {
					if (holes.get(i).getFirst() >= datagramLength) {
						// this would be executed if the last fragment indicates a shorter datagram than
						//   what has already been received
						holes.remove(i);
					}
					else {
						holes.get(i).setLast(datagramLength);
					}
				}
			}
		}

		Hole currentHole;
		int fragmentFirst = ipp.getFragmentOffsetI();
		int fragmentLast = ipp.getFragmentOffsetI() + ipp.getIPpayloadLengthI();

		//
		// Fragment Reassembly algorithm described in RFC 815
		////////////////////////////////////////////////////////////////////////////////////////////
		int count = 0;
		while (holes.size() > count) {

			// STEP 1: get the next hole from the list
			//    an empty Hole ArrayList indicates a complete datagram
			if (holes.size() == 0) {
				break; // can maybe return true here
			}
			currentHole = holes.get(count);

			// STEP 2: the fragment is to the right of the hole
			if (fragmentFirst > currentHole.getLast()) {
				count++;
				continue; // go to step 1
			}
			// STEP 3: the fragment is to the left of the hole
			if (fragmentLast < currentHole.getFirst()) {
				count++;
				continue; // go to step 1
			}

			// STEP 4: delete the current hole
			holes.remove(count);
			count++;

			// STEP 5: create a new hole to the left of the fragment
			if (fragmentFirst > currentHole.getFirst()) {
				holes.add(new Hole(currentHole.getFirst(), fragmentFirst-1));
			}
			// STEP 6: create a new hole to the right of the fragment
			//   this step also check if this is the last fragment of the datagram
			if (fragmentLast < currentHole.getLast() && ipp.isMoreFragments()) {
				holes.add(new Hole(fragmentLast+1, currentHole.getLast()));
			}

			// STEP 7: go to step 1
		}

		// STEP 8: return true if datagram is completely reassembled
		if (holes.size() == 0) {
			completed = true;
		}

		// make sure the length of the datagram is not >64K
		if ((ipp.getFragmentOffsetI() + ipp.getIPpayloadLengthI()) >= 64000) {
			sid = 3;
		}
		else {
			// add data to the data buffer
			//   NOTE: this overrides previously-stored fragment data
			for (int i=0; i<ipp.getIPpayloadLengthI(); i++) {
				// check if this data overlaps with previously-stored data
				if (totalDataBuffer.get(fragmentFirst+i) != ((byte) -128)) {
					sid = 2;
				}
				totalDataBuffer.set(fragmentFirst+i, ipp.getIPpayload()[i]);
			}
		}
		
		return completed;
	}

	public byte[] contructCompletedPacket() {
		IPPacket frag = fragments.get(0);
		byte[] headerBytes = new byte[14 + frag.getIHLi()*4];
		byte[] newBytes = new byte[headerBytes.length + datagramLength];

		// copy the fragment Ethernet and IP headers
		System.arraycopy(frag.getBytes(), 0, headerBytes, 0, headerBytes.length);

		//
		// edit the headers to fit the new completed datagram
		////////////////////////////////////////////////////////////////////////////////////////////

		// set DontFragment bit, MoreFragments bit, and FragmentOffset to zero
		headerBytes[20] = 0;
		headerBytes[21] = 0;

		// recalculate IP total length field
		int newTotalLength = headerBytes.length - 14 + datagramLength; // don't count ETH header

		headerBytes[17] = (byte) (newTotalLength & 0xFF);
		headerBytes[16] = (byte) ((newTotalLength >> 8) & 0xFF);

		// calculate new checksum
		byte[] newChecksum = new byte[2];
		newChecksum = calculateChecksum(headerBytes);

		headerBytes[24] = newChecksum[0];
		headerBytes[25] = newChecksum[1];

		//int tempI = Integer.parseUnsignedInt("DF", 16); // 1101 1111
		//newBytes[20] = (byte) (((byte) tempI) & newBytes[20]);

		// add the completed datagram
		System.arraycopy(headerBytes, 0, newBytes, 0, headerBytes.length);
		byte[] data = new byte[totalDataBuffer.size()];
		for (int i = 0; i<data.length; i++) {
			data[i] = totalDataBuffer.get(i);
		}

		System.arraycopy(headerBytes, 0, newBytes, 0, headerBytes.length);
		System.arraycopy(data, 0, newBytes, headerBytes.length, datagramLength);

		return newBytes;
	}

	private byte[] calculateChecksum(byte[] headerBytes) {
		byte[] checksum = new byte[2];

		int sum = 0;

		// loop through 16-bit values of the header
		for (int i=14; i<headerBytes.length; i+=2) {
			// skip the current checksum field
			if (i != 24) {
				sum += Byte.toUnsignedInt(headerBytes[i])*256 + 
						Byte.toUnsignedInt(headerBytes[i+1]);
			}
		}

		// move carry bits to least significant bit
		while (sum>65536) {
			sum = sum - 65536 + 1;
		}

		// flip every bit in sum
		sum = ~sum & 0xFFFF;

		// convert to two bytes
		checksum[1] = (byte) (sum & 0xFF);
		checksum[0] = (byte) ((sum >> 8) & 0xFF);

		return checksum;
	}

	public int getSid() {
		return sid;
	}

	public void setSid(int sid) {
		this.sid = sid;
	}

	public String getSrcIPaddS() {
		return srcIPaddS;
	}

	public void setSrcIPaddS(String srcIPadd) {
		this.srcIPaddS = srcIPadd;
	}

	public String getDstIPaddS() {
		return dstIPaddS;
	}

	public void setDstIPaddS(String dstIPadd) {
		this.dstIPaddS = dstIPadd;
	}

	public String getIPprotocolS() {
		return IPprotocolS;
	}

	public void setIPprotocolS(String iPprotocol) {
		IPprotocolS = iPprotocol;
	}

	public int getIPid() {
		return IPid;
	}

	public void setIPid(int iPid) {
		IPid = iPid;
	}

	public ArrayList<Byte> getTotalDataBuffer() {
		return totalDataBuffer;
	}

	public void setTotalDataBuffer(ArrayList<Byte> totalDataBuffer) {
		this.totalDataBuffer = totalDataBuffer;
	}

	public int getDatagramLength() {
		return datagramLength;
	}

	public void setDatagramLength(int datagramLength) {
		this.datagramLength = datagramLength;
	}

	public IPPacket getTotalIPp() {
		return totalIPp;
	}

	public void setTotalIPp(IPPacket totalIPp) {
		this.totalIPp = totalIPp;
	}

	public ArrayList<IPPacket> getFragments() {
		return fragments;
	}

	public void setFragments(ArrayList<IPPacket> fragments) {
		this.fragments = fragments;
	}

	public ArrayList<Hole> getHoles() {
		return holes;
	}

	public void setHoles(ArrayList<Hole> holes) {
		this.holes = holes;
	}

	public long getTimeoutTime() {
		return timeoutTime;
	}

	public void setTimeoutTime(long timeoutTime) {
		this.timeoutTime = timeoutTime;
	}

	public boolean isDropped() {
		return dropped;
	}

	public void setDropped(boolean dropped) {
		this.dropped = dropped;
	}
}