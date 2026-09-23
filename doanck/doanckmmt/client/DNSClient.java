package doanckmmt.client;

import java.io.ByteArrayOutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

public class DNSClient {

    private static String serverIp = "127.0.0.1"; // Mặc định localhost
    private static int serverPort = 5353;         // Cổng mặc định cho Server nhóm

    public static void main(String[] args) {
        if (args.length < 1) {
            System.out.println("==========================================================================");
            System.out.println("Cú pháp: java DNSClient <domain-hoặc-ip> [Type] [Server_IP] [Server_Port]");
            System.out.println("Ví dụ tra cứu Server Máy B : java DNSClient nhom14.local A 192.168.1.15 5353");
            System.out.println("Ví dụ tra cứu Google DNS   : java DNSClient google.com A 8.8.8.8 53");
            System.out.println("Ví dụ tra cứu ngược PTR   : java DNSClient 8.8.8.8 PTR 8.8.8.8 53");
            System.out.println("==========================================================================");
            return;
        }

        String target = args[0];
        String queryTypeStr = (args.length > 1) ? args[1].toUpperCase() : "A";

        if (args.length > 2) serverIp = args[2];
        if (args.length > 3) serverPort = Integer.parseInt(args[3]);

        // Nhận diện IP tự chuyển sang PTR nếu không nhập type
        if (isIPv4(target) && args.length == 1) {
            queryTypeStr = "PTR";
        }

        int queryType = getRecordTypeNum(queryTypeStr);
        String formattedDomain = target;

        if (queryTypeStr.equals("PTR") && isIPv4(target)) {
            formattedDomain = reverseIPv4Domain(target);
        }

        try {
            System.out.println("\n[+] Đang gửi câu hỏi đến DNS Server [" + serverIp + ":" + serverPort + "]...");
            System.out.println("[+] Tra cứu: " + target + " (Record: " + queryTypeStr + ")");

            long startTime = System.currentTimeMillis(); // Đo thời gian phản hồi
            byte[] responseBuffer = sendDNSQuery(serverIp, serverPort, formattedDomain, queryType);
            long endTime = System.currentTimeMillis();

            System.out.println("[+] Thời gian phản hồi (Latency): " + (endTime - startTime) + " ms");
            parseDNSResponse(responseBuffer);

        } catch (Exception e) {
            System.err.println("[-] Lỗi: Không thể nhận dữ liệu từ DNS Server (Timeout hoặc Sai IP/Port).");
        }
    }

    private static byte[] sendDNSQuery(String dnsServer, int port, String domain, int queryType) throws Exception {
        ByteArrayOutputStream queryStream = new ByteArrayOutputStream();

        // 1. DNS HEADER (12 Bytes)
        ByteBuffer header = ByteBuffer.allocate(12);
        header.putShort((short) (Math.random() * 0xFFFF)); // Transaction ID
        header.putShort((short) 0x0100);                    // Flags: Recursion Desired
        header.putShort((short) 1);                         // QDCOUNT = 1
        header.putShort((short) 0);                         // ANCOUNT
        header.putShort((short) 0);                         // NSCOUNT
        header.putShort((short) 0);                         // ARCOUNT
        queryStream.write(header.array());

        // 2. QUESTION SECTION
        String[] labels = domain.split("\\.");
        for (String label : labels) {
            queryStream.write(label.length());
            queryStream.write(label.getBytes(StandardCharsets.UTF_8));
        }
        queryStream.write(0); // Byte 0x00 kết thúc

        ByteBuffer qFields = ByteBuffer.allocate(4);
        qFields.putShort((short) queryType);
        qFields.putShort((short) 1); // QCLASS = IN
        queryStream.write(qFields.array());

        // 3. GUI QUA UDP SOCKET
        try (DatagramSocket socket = new DatagramSocket()) {
            socket.setSoTimeout(3000); // Timeout 3 giây
            InetAddress serverAddr = InetAddress.getByName(dnsServer);
            byte[] queryData = queryStream.toByteArray();

            DatagramPacket sendPacket = new DatagramPacket(queryData, queryData.length, serverAddr, port);
            socket.send(sendPacket);

            byte[] receiveBuffer = new byte[1024];
            DatagramPacket receivePacket = new DatagramPacket(receiveBuffer, receiveBuffer.length);
            socket.receive(receivePacket);

            return receivePacket.getData();
        }
    }

    private static void parseDNSResponse(byte[] response) {
        ByteBuffer buffer = ByteBuffer.wrap(response);

        buffer.getShort(); // Skip ID
        short flags = buffer.getShort();
        short qdCount = buffer.getShort();
        short anCount = buffer.getShort();
        buffer.getShort(); buffer.getShort(); // Skip NS & AR Count

        int rcode = flags & 0x000F;
        if (rcode != 0) {
            System.out.println("[-] Máy chủ DNS trả về lỗi (RCODE = " + rcode + "). Không tìm thấy tên miền!");
            return;
        }

        System.out.println("\n[=>] KẾT QUẢ TRẢ VỀ (" + anCount + " bản ghi):");

        // Bỏ qua Question
        for (int i = 0; i < qdCount; i++) {
            readDomainName(buffer, response);
            buffer.getShort(); buffer.getShort();
        }

        // Đọc Answers
        for (int i = 0; i < anCount; i++) {
            String name = readDomainName(buffer, response);
            int type = buffer.getShort() & 0xFFFF;
            buffer.getShort(); // Skip Class
            int ttl = buffer.getInt();
            int rdLength = buffer.getShort() & 0xFFFF;

            System.out.print("   • " + name + " [TTL: " + ttl + "s] -> ");

            if (type == 1 && rdLength == 4) { // Record A
                byte[] ipBytes = new byte[4];
                buffer.get(ipBytes);
                try {
                    InetAddress ip = InetAddress.getByAddress(ipBytes);
                    System.out.println("Địa chỉ IPv4: " + ip.getHostAddress());
                } catch (Exception e) {}
            } else if (type == 12 || type == 5) { // PTR hoặc CNAME
                String targetName = readDomainName(buffer, response);
                System.out.println("Tên miền trỏ đến: " + targetName);
            } else {
                buffer.position(buffer.position() + rdLength);
                System.out.println("Record Type " + type + " (Đã nhận " + rdLength + " bytes)");
            }
        }
        System.out.println();
    }

    private static String readDomainName(ByteBuffer buffer, byte[] fullResponse) {
        StringBuilder domain = new StringBuilder();
        boolean jumped = false;
        int originalPosition = -1;

        while (true) {
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
            default: return 1;
        }
    }

    private static boolean isIPv4(String input) {
        return input.matches("^(\\d{1,3}\\.){3}\\d{1,3}$");
    }

    private static String reverseIPv4Domain(String ip) {
        String[] parts = ip.split("\\.");
        return parts[3] + "." + parts[2] + "." + parts[1] + "." + parts[0] + ".in-addr.arpa";
    }
}