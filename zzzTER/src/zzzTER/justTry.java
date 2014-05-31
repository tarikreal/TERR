package zzzTER;

import java.awt.print.PageFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;

import java.io.*;
import java.math.BigInteger;

public class justTry {
	public static void main(String[] args) throws Exception {
		List<PcapIf> alldevs = new ArrayList<PcapIf>(); // Will be filled with
														// NIC's
		StringBuilder errbuf = new StringBuilder();

		// First, get a list of devices on this System
		int r = Pcap.findAllDevs(alldevs, errbuf);
		if ((r == Pcap.NOT_OK) || alldevs.isEmpty()) {
			System.out.printf("Can't read list of devices, error is %s",
					errbuf.toString());
			return;
		}// End if
			// Iterate through all the interface and get the HW address
		for (final PcapIf i : alldevs) {
			final byte[] mac = i.getHardwareAddress();
			if (mac == null) {
				continue; // Interface doesn't have a hardware address
			} // End if
			System.out.printf("%s=%s\n", i.getName(), asString(mac));
		} // End for

		BigInteger na = new BigInteger("32132123132121321231313211313131321");
		BigInteger naa = new BigInteger("213132132123132132131321");
		
		System.out.println(na.add(naa));
	} // End f main()

	private static String asString(final byte[] mac) {
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

} // End of justTry class
