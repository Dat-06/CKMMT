package doanckmmt.client;

import java.io.ByteArrayOutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

public class DNSClient {

    public static void main(String[] args) {
        // Có thể thay đổi domain thành facebook.com, google.com, youtube.com...
        String domain = "facebook.com";
        String type = "A";
        String serverIp = "100.92.122.114"; // IP Tailscale Server của bạn
        int port = 5354;

        if (args.length >= 1) domain = args[0];
        if (args.length >= 2) type = args[1].toUpperCase();
        if (args.length >= 3) serverIp = args[2];
        if (args.length >= 4) port = Integer.parseInt(args[3]);

        System.out.println("==========================================================================");
        System.out.println("                 DNS CLIENT - CÔNG CỤ TRA CỨU DNS                         ");
        System.out.println("==========================================================================");
        System.out.println("[+] Target Server  : " + serverIp + ":" + port);
        System.out.println("[+] Query Domain   : " + domain);
        System.out.println("[+] Record Type    : " + type);

        try {
            long startTime = System.currentTimeMillis();
            byte[] response = sendDNSQuery(serverIp, port, domain, getRecordTypeNum(type));
            long latency = System.currentTimeMillis() - startTime;

            System.out.println("\n[✓] KẾT NỐI THÀNH CÔNG! Thời gian phản hồi (Latency): " + latency + " ms");
            parseDNSResponse(response);

        } catch (Exception e) {
            System.err.println("\n[-] Lỗi Client: " + e.getMessage());
        }
    }

    private static byte[] sendDNSQuery(String dnsServer, int port, String domain, int queryType) throws Exception {
        ByteArrayOutputStream queryStream = new ByteArrayOutputStream();

        ByteBuffer header = ByteBuffer.allocate(12);
        header.putShort((short) (Math.random() * 0xFFFF));
        header.putShort((short) 0x0100);
        header.putShort((short) 1);
        header.putShort((short) 0);
        header.putShort((short) 0);
        header.putShort((short) 0);
        queryStream.write(header.array());

        String[] labels = domain.split("\\.");
        for (String label : labels) {
            queryStream.write(label.length());
            queryStream.write(label.getBytes(StandardCharsets.UTF_8));
        }
        queryStream.write(0);

        ByteBuffer qFields = ByteBuffer.allocate(4);
        qFields.putShort((short) queryType);
        qFields.putShort((short) 1);
        queryStream.write(qFields.array());

        try (DatagramSocket socket = new DatagramSocket()) {
            socket.setSoTimeout(4000);
            InetAddress serverAddr = InetAddress.getByName(dnsServer);
            byte[] queryData = queryStream.toByteArray();

            DatagramPacket sendPacket = new DatagramPacket(queryData, queryData.length, serverAddr, port);
            socket.send(sendPacket);

            byte[] receiveBuffer = new byte[1024];
            DatagramPacket receivePacket = new DatagramPacket(receiveBuffer, receiveBuffer.length);
            socket.receive(receivePacket);

            byte[] actualData = new byte[receivePacket.getLength()];
            System.arraycopy(receiveBuffer, 0, actualData, 0, receivePacket.getLength());
            return actualData;
        }
    }

    private static void parseDNSResponse(byte[] response) {
        ByteBuffer buffer = ByteBuffer.wrap(response);

        buffer.getShort();
        short flags = buffer.getShort();
        short qdCount = buffer.getShort();
        short anCount = buffer.getShort();
        buffer.getShort(); buffer.getShort();

        int rcode = flags & 0x000F;
        if (rcode != 0) {
            System.out.println("[-] DNS Server báo lỗi (RCODE = " + rcode + "). Không tìm thấy bản ghi!");
            return;
        }

        System.out.println("\n[=>] KẾT QUẢ PHÂN TÍCH GÓI TIN RESPONSE (" + anCount + " Answer Records):");

        for (int i = 0; i < qdCount; i++) {
            readDomainName(buffer, response);
            buffer.getShort(); buffer.getShort();
        }

        for (int i = 0; i < anCount; i++) {
            String name = readDomainName(buffer, response);
            int type = buffer.getShort() & 0xFFFF;
            buffer.getShort();
            int ttl = buffer.getInt();
            int rdLength = buffer.getShort() & 0xFFFF;

            System.out.print("   📌 [" + getRecordTypeName(type) + "] " + name + " (TTL: " + ttl + "s) -> ");

            if (type == 1 && rdLength == 4) {
                byte[] ipBytes = new byte[4];
                buffer.get(ipBytes);
                try {
                    System.out.println(InetAddress.getByAddress(ipBytes).getHostAddress());
                } catch (Exception e) {}
            } else if (type == 28 && rdLength == 16) {
                byte[] ipBytes = new byte[16];
                buffer.get(ipBytes);
                try {
                    System.out.println(InetAddress.getByAddress(ipBytes).getHostAddress());
                } catch (Exception e) {}
            } else if (type == 5 || type == 12) {
                System.out.println(readDomainName(buffer, response));
            } else {
                buffer.position(buffer.position() + rdLength);
                System.out.println("Raw Data (" + rdLength + " bytes)");
            }
        }
        System.out.println();
    }

    private static String readDomainName(ByteBuffer buffer, byte[] fullResponse) {
        StringBuilder domain = new StringBuilder();
        boolean jumped = false;
        int originalPosition = -1;

        while (buffer.hasRemaining()) {
            int length = buffer.get() & 0xFF;
            if ((length & 0xC0) == 0xC0) {
                if (!jumped) originalPosition = buffer.position() + 1;
                int b2 = buffer.get() & 0xFF;
                int offset = ((length & 0x3F) << 8) | b2;
                buffer.position(offset);
                jumped = true;
                continue;
            }
            if (length == 0) break;
            byte[] labelBytes = new byte[length];
            buffer.get(labelBytes);
            domain.append(new String(labelBytes, StandardCharsets.UTF_8)).append(".");
        }

        if (jumped) buffer.position(originalPosition);
        if (domain.length() > 0) domain.setLength(domain.length() - 1);
        return domain.toString();
    }

    private static int getRecordTypeNum(String type) {
        switch (type) {
            case "A": return 1;
            case "CNAME": return 5;
            case "PTR": return 12;
            case "MX": return 15;
            case "TXT": return 16;
            case "AAAA": return 28;
            default: return 1;
        }
    }

    private static String getRecordTypeName(int type) {
        switch (type) {
            case 1: return "IPv4 (A)";
            case 28: return "IPv6 (AAAA)";
            case 5: return "CNAME";
            case 15: return "MX";
            case 16: return "TXT";
            case 12: return "PTR";
            default: return "TYPE_" + type;
        }
    }
}