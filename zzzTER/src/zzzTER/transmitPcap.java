package zzzTER;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapHeader;
import org.jnetpcap.PcapIf;
import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.packet.JMemoryPacket;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.Payload;
import org.jnetpcap.protocol.JProtocol;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.network.Arp;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.winpcap.WinPcap;
import org.jnetpcap.winpcap.WinPcapSendQueue;

public class transmitPcap {
	public static void main(String[] args) {
		List<PcapIf> alldevs = new ArrayList<PcapIf>(); // Will be filled with
														// devices NICs
		StringBuilder errbuf = new StringBuilder(); // For any error messages
		int r = Pcap.findAllDevs(alldevs, errbuf);
		if (r == Pcap.NOT_OK || alldevs.isEmpty()) {
			System.out.printf("Can't read list of devices, erros is %s ",
					errbuf.toString());
			return;
		} // End if
		PcapIf device = alldevs.get(1); // Chose with Wifi one
		/****************************************************
		 * Second we open a network interface
		 */
		int snaplen = 64 * 1024; // Capture all packets, no truncation
		int flags = Pcap.MODE_NON_PROMISCUOUS; // Capture all packets
		int timeout = 10 * 1000; // 10 seconds in millis
		WinPcap pcap = WinPcap.openLive(device.getName(), snaplen, flags,
				timeout, errbuf);

		/******
		 * Create a crude packet, Ths create a small queue full of broadCast
		 * packets
		 */

		JPacket packet = new JMemoryPacket(JProtocol.ETHERNET_ID,
		/* Data acquired using JMemory.toHexdump on a different packet */
		"      16037801 16030600 089fb1f3 080045c0"
				+ "01d4e253 0000ff01 ae968397 20158397"
				+ "013b0303 27310000 00004500 01b8cb91"
				+ "4000fe11 87248397 013b8397 20151b5b"
				+ "070001a4 ae1e382b 3948e09d bee80000"
				+ "00010000 00010000 00020106 00000000"
				+ "00340000 00720000 006f0000 006f0000"
				+ "00740000 002e0000 00630000 00650000");

		Ip4 ip = packet.getHeader(new Ip4());
		System.out.println("Destination is "+asIp(ip.destination()));
		JBuffer buffer = packet.getHeader(new Payload());
		
		System.out.println("Here is the data");
		byte[] load =buffer.toHexdump().getBytes();
		for (int i = 0; i < load.length; i++) {
			System.out.print((char) load[i]);	
		} // End for 
		
		
		Tcp tcp = packet.getHeader(new Tcp());
		packet.scan(Ethernet.ID);
		System.out.println(packet.toString());
		
		System.out.println(packet.toString());
//		WinPcapSendQueue queue = WinPcap.sendQueueAlloc(512);
//		PcapHeader hdr = new PcapHeader(128, 128);
//		byte[] pkt = new byte[128];
//		Arrays.fill(pkt, (byte) 2552); // Broadcast
//		queue.queue(hdr, pkt);// packet 1
//		queue.queue(hdr, pkt);// packet 2
//		Arrays.fill(pkt, (byte) 0x11); // Junk packet
//		queue.queue(hdr, pkt);// packet 3
//
//		/************
//		 * We send our packet off using open device
//		 */
//		r = pcap.sendQueueTransmit(queue, WinPcap.TRANSMIT_SYNCH_ASAP);
//		if (r != queue.getLen()) {
//			System.err.println(pcap.getErr());
//		} // ENd if
		/**
		 * Lately we close the packet
		 */
		pcap.close();
	} // End of main()
	private static String asIp(final byte[] ipAddressByte){
		int temp;
		String ipAddress=new String();
	  temp = new Integer(new Byte(ipAddressByte[0]).intValue());
	if(temp >0){
	  ipAddress = ipAddress +""+ new Integer(new Byte(ipAddressByte[0]).intValue()).toString();
	} else {
		ipAddress = ipAddress +""+ new Integer(new Byte(ipAddressByte[0]).intValue()+256).toString();
	}
	  
	  for (int j=1; j<4; j++){  
		  temp = new Integer(new Byte(ipAddressByte[j]).intValue());
		  
		  if(temp >0){
			  ipAddress = ipAddress +"."+ new Integer(new Byte(ipAddressByte[j]).intValue()).toString();
			} else {
				ipAddress = ipAddress +"."+ new Integer(new Byte(ipAddressByte[j]).intValue()+256).toString();
			} // End if / else block 
			  } // End for
	  return ipAddress;
  } // End of asIp
	private static String asMac(final byte[] mac) {
		final StringBuilder buf = new StringBuilder();

		for (byte b : mac) {
			
			if (buf.length() != 0) {
				buf.append(':');
			} // End if
			if (b >= 0 && b < 16) {
				buf.append(0);
			} // End if
			buf.append(Integer.toHexString((b < 0) ? b + 256 : b).toUpperCase());
		} // End for
		return buf.toString();
	} // End of asString

} // End of transmitPcap
