package com.g120s.janus.discovery;

import org.junit.jupiter.api.Test;
import org.pcap4j.packet.ArpPacket;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.UnknownPacket;
import org.pcap4j.packet.factory.PacketFactories;
import org.pcap4j.packet.namednumber.ArpOperation;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.util.MacAddress;

import java.net.InetAddress;

import static org.junit.jupiter.api.Assertions.*;

/**
 * ARP scanning depends on captured frames being decoded into typed packets.
 *
 * <p>pcap4j needs a {@code PacketFactoryBinder} for that. With only pcap4j-core on
 * the classpath every frame decodes as an {@link UnknownPacket}, so
 * {@code packet.get(ArpPacket.class)} returns {@code null} and ARP finds nothing at
 * all — silently, even when running with CAP_NET_RAW. The library only hints at
 * this with "No PacketFactoryBinder is available", which reads like noise.
 */
class PacketFactoryTests {

    @Test
    void ethernetFramesDecodeToTypedPackets() throws Exception {
        // Round-trip a real ARP reply through the decoder the way L2Scanner sees it.
        ArpPacket arp = new ArpPacket.Builder()
                .hardwareType(org.pcap4j.packet.namednumber.ArpHardwareType.ETHERNET)
                .protocolType(EtherType.IPV4)
                .hardwareAddrLength((byte) MacAddress.SIZE_IN_BYTES)
                .protocolAddrLength((byte) 4)
                .operation(ArpOperation.REPLY)
                .srcHardwareAddr(MacAddress.getByName("00:11:22:33:44:55"))
                .srcProtocolAddr(java.net.InetAddress.getByName("192.168.1.50"))
                .dstHardwareAddr(MacAddress.getByName("aa:bb:cc:dd:ee:ff"))
                .dstProtocolAddr(InetAddress.getByName("192.168.1.10"))
                .build();
        EthernetPacket frame = new EthernetPacket.Builder()
                .srcAddr(MacAddress.getByName("00:11:22:33:44:55"))
                .dstAddr(MacAddress.getByName("aa:bb:cc:dd:ee:ff"))
                .type(EtherType.ARP)
                .payloadBuilder(new org.pcap4j.packet.SimpleBuilder(arp))
                .paddingAtBuild(true)
                .build();

        Packet decoded = PacketFactories.getFactory(Packet.class, EtherType.class)
                .newInstance(frame.getRawData(), 14, frame.length() - 14, EtherType.ARP);

        assertNotNull(decoded);
        assertInstanceOf(ArpPacket.class, decoded,
                "a captured ARP frame must decode to ArpPacket, otherwise ARP scanning "
                        + "silently returns nothing; check for pcap4j-packetfactory-static");
        ArpPacket parsed = (ArpPacket) decoded;
        assertEquals("192.168.1.50", parsed.getHeader().getSrcProtocolAddr().getHostAddress());
        assertEquals("00:11:22:33:44:55", parsed.getHeader().getSrcHardwareAddr().toString().toLowerCase());
    }

    @Test
    void aPacketFactoryBinderIsPresent() {
        // The binder is what the "No PacketFactoryBinder" warning complains about.
        Packet sample = PacketFactories.getFactory(Packet.class, EtherType.class)
                .newInstance(new byte[]{0, 0, 0, 0}, 0, 4, EtherType.IPV4);
        assertNotNull(sample);
    }
}
