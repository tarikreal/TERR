package zzzTER;

import java.io.BufferedWriter;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.ObjectInputStream.GetField;
import java.util.StringTokenizer;

import javax.swing.plaf.basic.BasicFileChooserUI;

import org.bouncycastle.util.encoders.Hex;
import org.jnetpcap.*;
import org.jnetpcap.packet.JMemoryPacket;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.protocol.JProtocol;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.network.Arp;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Tcp;

public class packets {
	public static void main(String[] args) throws Exception {
		String filename = "F:/Users/Home/Desktop/second.txt";

		BufferedWriter bufferedwriter = new BufferedWriter(new FileWriter(
				filename));

		JPacket packet = new JMemoryPacket(JProtocol.ETHERNET_ID,
				" 111801bf 6adc0025 4bb7afec 08004500 "
						+ " 0041a983 40004006 d69ac0a8 00342f8c "
						+ " ca30c3ef 008f2e80 11f52ea8 4b578018 "
						+ " ffffa6ea 00000101 080a152e ef03002a "
						+ " 2c943538 322e3430 204e4f4f 500d0f");

		// JPacket packetarp = new JMemoryPacket(JProtocol.ETHERNET_ID,
		// "  "
		// + "dc a9 71 b8 94 21 00 07 cb 00 01 00 08 06 00 01"
		// + "08 00 06 04 00 02 00 07 cb 00 01 00 0a 2f ff fe"
		// + "dc a9 71 b8 94 21 0a 28 86 97");

		JPacket packetarp = new JMemoryPacket(JProtocol.ETHERNET_ID,
				"ff ff ff ff ff ff dc a9 71 b8 94 21 08 06 00 01"
						+ "08 00 06 04 00 01 dc a9 71 b8 94 21 0a 28 86 97"
						+ "00 00 00 00 00 00 0a 2f ff fe");

		Ip4 ip = packet.getHeader(new Ip4());
		Tcp tcp = packet.getHeader(new Tcp());

		Arp arp = packetarp.getHeader(new Arp());

		System.out.println("This is ARP !");
		System.out.println(arp);
		// Source
		System.out.println("IP source : " + asIp(arp.spa()));
		System.out.println("Hardware source : " + asMAC(arp.sha()));
		System.out.println();
		// Destination

		System.out.println("IP Destination : " + asIp(arp.tpa()));
		System.out.println("Hardware Destination: " + asMAC(arp.tha()));
		
	   
		
		
		System.out.println("Destination in the packet "+hexIpAdress(asIp(arp.spa())));
		System.out.println("Source in the packet "+hexIpAdress(asIp(arp.spa())));
		
		
		tcp.destination(80);

		ip.checksum(ip.calculateChecksum());
		tcp.checksum(tcp.calculateChecksum());

		packet.scan(Ethernet.ID);
		
		
		
		bufferedwriter.write(packet.toString());

		// System.out.println(packet);
		bufferedwriter.close();
	} // End of main()

	private static String asIp(final byte[] ipAddressByte) {
		int temp;
		String ipAddress = new String();
		temp = new Integer(new Byte(ipAddressByte[0]).intValue());
		if (temp > 0) {
			ipAddress = ipAddress
					+ ""
					+ new Integer(new Byte(ipAddressByte[0]).intValue())
							.toString();
		} else {
			ipAddress = ipAddress
					+ ""
					+ new Integer(new Byte(ipAddressByte[0]).intValue() + 256)
							.toString();
		} // End if else/ block 

		for (int j = 1; j < 4; j++) {
			temp = new Integer(new Byte(ipAddressByte[j]).intValue());

			if (temp > 0) {
				ipAddress = ipAddress
						+ "."
						+ new Integer(new Byte(ipAddressByte[j]).intValue())
								.toString();
			} else {
				ipAddress = ipAddress
						+ "."
						+ new Integer(
								new Byte(ipAddressByte[j]).intValue() + 256)
								.toString();
			} // End if / else block
		} // End for
		return ipAddress;
	} // End of asIp

	private static String asMAC(final byte[] mac) {
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

	public final static int parseNumericAddress(String ipaddr) {

		// Check if the string is valid

		if (ipaddr == null || ipaddr.length() < 7 || ipaddr.length() > 15)
			return 0;

		// Check the address string, should be n.n.n.n format

		StringTokenizer token = new StringTokenizer(ipaddr, ".");
		if (token.countTokens() != 4)
			return 0;

		int ipInt = 0;

		while (token.hasMoreTokens()) {

			// Get the current token and convert to an integer value

			String ipNum = token.nextToken();

			try {

				// Validate the current address part

				int ipVal = Integer.valueOf(ipNum).intValue();
				if (ipVal < 0 || ipVal > 255)
					return 0;

				// Add to the integer address

				ipInt = (ipInt << 8) + ipVal;
			} catch (NumberFormatException ex) {
				return 0;
			} // End of try/catch block
		} // End while

		// Return the integer address

		return ipInt;
	} // End of parseNumericAddress
	
	
     public static String hexIpAdress(String address){
    	 String hexIp = Integer.toHexString(parseNumericAddress(address)); 
 		StringBuilder sb = new StringBuilder("0");
 		while(hexIp.length()<=7){
 		if(hexIp.length() <=7){
 			hexIp = sb.append(hexIp).toString();
 		} // End if 
 		} // End while 
 		return hexIp;
     } // End of hexIpAdress 


} // End of packets 