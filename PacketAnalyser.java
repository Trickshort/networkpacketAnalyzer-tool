import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.tcpip.Udp;

import java.util.ArrayList;
import java.util.List;

public class PacketAnalyzer {

    public static void main(String[] args) {
        List<PcapIf> alldevs = new ArrayList<>(); // Will hold list of devices
        StringBuilder errbuf = new StringBuilder(); // For any error msgs

        // Getting a list of devices
        int r = Pcap.findAllDevs(alldevs, errbuf);
        if (r != Pcap.OK || alldevs.isEmpty()) {
            System.err.printf("Can't read list of devices, error is %s", errbuf.toString());
            return;
        }

        PcapIf device = alldevs.get(0); // Choosing the first device
        System.out.printf("Choosing '%s' on your behalf:\n", (device.getDescription() != null) ? device.getDescription() : device.getName());

        int snaplen = 64 * 1024; // Capture all packets, no truncation
        int flags = Pcap.MODE_PROMISCUOUS; // capture all packets
        int timeout = 10 * 1000; // 10 seconds in millis
        Pcap pcap = Pcap.openLive(device.getName(), snaplen, flags, timeout, errbuf);

        if (pcap == null) {
            System.err.printf("Error while opening device for capture: %s\n", errbuf.toString());
            return;
        }

        PcapPacketHandler<String> jpacketHandler = new PcapPacketHandler<>() {
            public void nextPacket(PcapPacket packet, String user) {
                Ip4 ip = new Ip4();
                Tcp tcp = new Tcp();
                Udp udp = new Udp();

                if (packet.hasHeader(ip)) {
                    byte[] sIP = new byte[4];
                    byte[] dIP = new byte[4];
                    ip.source(sIP);
                    ip.destination(dIP);

                    String srcIp = org.jnetpcap.packet.format.FormatUtils.ip(sIP);
                    String dstIp = org.jnetpcap.packet.format.FormatUtils.ip(dIP);
                    int protocol = ip.type();

                    String summary = String.format("Source IP: %s, Destination IP: %s, Protocol: %d", srcIp, dstIp, protocol);

                    if (packet.hasHeader(tcp)) {
                        summary += String.format(", Source Port: %d, Destination Port: %d, TCP Packet", tcp.source(), tcp.destination());
                    } else if (packet.hasHeader(udp)) {
                        summary += String.format(", Source Port: %d, Destination Port: %d, UDP Packet", udp.source(), udp.destination());
                    } else {
                        summary += ", Unknown Packet";
                    }

                    System.out.println(summary);
                }
            }
        };

        // Start the capture
        pcap.loop(Pcap.LOOP_INFINATE, jpacketHandler, "jNetPcap rocks!");

        // Close the pcap handle
        pcap.close();
    }
}
