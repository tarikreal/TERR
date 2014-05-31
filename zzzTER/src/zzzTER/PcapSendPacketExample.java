package zzzTER;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;

public class PcapSendPacketExample {
	public static void main(String[] args) {
		List<PcapIf> alldevs = new ArrayList<PcapIf>(); // Will be filled with
														// NICs
		StringBuilder errbuf = new StringBuilder(); // For any error msgs

		/***************************************************************************
		 * First get a list of devices on this system
		 **************************************************************************/
		int r = Pcap.findAllDevs(alldevs, errbuf);
		if (r == Pcap.NOT_OK || alldevs.isEmpty()) {
			System.err.printf("Can't read list of devices, error is %s",
					errbuf.toString());
			return;
		}
		

		PcapIf device = alldevs.get(1); // We know we have atleast 1 device

		/*****************************************
		 * Second we open a network interface
		 *****************************************/
		int snaplen = 64 * 1024; // Capture all packets, no trucation
		int flags = Pcap.MODE_PROMISCUOUS; // capture all packets
		int timeout = 10 * 1000; // 10 seconds in millis
		Pcap pcap = Pcap.openLive(device.getName(), snaplen, flags, timeout,
				errbuf);
		
		/*******************************************************
		 * Third we create our crude packet we will transmit out This creates a
		 * broadcast packet
		 *******************************************************/
		byte[] a = new byte[14];
		Arrays.fill(a, (byte) 0x22);
		ByteBuffer b = ByteBuffer.wrap(a);

		 /*******************************************************
		 * Fourth We send our packet off using open device
		 *******************************************************/
		 if (pcap.sendPacket(b) != Pcap.OK) {
		 System.err.println(pcap.getErr());
		 }
		
		/********************************************************
		 * Lastly we close
		 ********************************************************/
		pcap.close();
	}
}