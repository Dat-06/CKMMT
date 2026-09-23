package doanckmmt.server;

import java.io.ByteArrayOutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

public class DNSServer {

    private static final int PORT = 5354; // Cổng UDP Server lắng nghe
    private static final Map<String, String> dnsTable = new HashMap<>();

    public static void main(String[] args) {
        // 1. Khởi tạo Cơ sở dữ liệu DNS giả lập của nhóm
        initDNSTable();

        System.out.println("=================================================");
        System.out.println("   DNS SERVER NỘI BỘ (MÔ HÌNH CLIENT - SERVER)   ");
        System.out.println("=================================================");
        System.out.println("[+] Server đang chạy và lắng nghe tại cổng UDP: " + PORT);
        System.out.println("[+] Đã tải " + dnsTable.size() + " bản ghi DNS nội bộ.");
        System.out.println("[+] Đang chờ truy vấn từ DNS Client...\n");

        try (DatagramSocket socket = new DatagramSocket(PORT)) {
            byte[] receiveBuffer = new byte[1024];

            while (true) {
                // Nhận gói tin Query từ Máy A (Client)
                DatagramPacket receivePacket = new DatagramPacket(receiveBuffer, receiveBuffer.length);
                socket.receive(receivePacket);

                InetAddress clientAddress = receivePacket.getAddress();
                int clientPort = receivePacket.getPort();

                System.out.println("-------------------------------------------------");
                System.out.println("[!] Nhận yêu cầu truy vấn từ Client IP: " + clientAddress.getHostAddress() + ":" + clientPort);

                // Tạo gói tin Response trả lời
                byte[] responseData = processQueryAndBuildResponse(receivePacket.getData());

                // Gửi trả gói tin Response về cho Máy A
                DatagramPacket sendPacket = new DatagramPacket(
                        responseData, responseData.length, clientAddress, clientPort
                );
                socket.send(sendPacket);
                System.out.println("[=>] Đã gửi gói tin DNS Response trả lời cho Client.");
            }
        } catch (Exception e) {
            System.err.println("[-] Lỗi Server: " + e.getMessage());
            e.printStackTrace();
        }
    }

    // Khởi tạo các tên miền test của nhóm
    private static void initDNSTable() {
        dnsTable.put("nhom14.local", "192.168.1.100");
        dnsTable.put("mywebsite.com", "10.0.0.88");
        dnsTable.put("google.com", "142.250.198.46");
        // Bản ghi ngược PTR (3.2.1.10.in-addr.arpa -> server1.local)
        dnsTable.put("100.1.168.192.in-addr.arpa", "nhom14.local");
    }

    // Xử lý và đóng gói DNS Response
    private static byte[] processQueryAndBuildResponse(byte[] request) throws Exception {
        ByteBuffer buffer = ByteBuffer.wrap(request);

        // Đọc Header từ Client
        short id = buffer.getShort();
        short flags = buffer.getShort();
        short qdCount = buffer.getShort();

        // Bỏ qua phần Header còn lại
        buffer.getShort(); buffer.getShort(); buffer.getShort();

        // Đọc tên miền từ phần Question
        int questionStartPos = buffer.position();
        String queriedDomain = readDomainName(buffer);
        short qType = buffer.getShort();
        short qClass = buffer.getShort();

        int questionLength = buffer.position() - questionStartPos;

        System.out.println("    + Domain hỏi: [" + queriedDomain + "]");
        System.out.println("    + Record Type: " + qType);

        ByteArrayOutputStream responseStream = new ByteArrayOutputStream();

        // --- 1. BUILD RESPONSE HEADER (12 Bytes) ---
        ByteBuffer header = ByteBuffer.allocate(12);
        header.putShort(id); // Giữ nguyên Transaction ID của Client
        header.putShort((short) 0x8180); // Flags: Standard response, No error, Recursion Available
        header.putShort((short) 1); // QDCOUNT = 1

        String resolvedIpOrDomain = dnsTable.get(queriedDomain.toLowerCase());

        if (resolvedIpOrDomain != null) {
            header.putShort((short) 1); // ANCOUNT = 1 (Tìm thấy 1 kết quả)
        } else {
            header.putShort((short) 0); // ANCOUNT = 0 (Không tìm thấy domain)
        }

        header.putShort((short) 0); // NSCOUNT
        header.putShort((short) 0); // ARCOUNT
        responseStream.write(header.array());

        // --- 2. COPY QUESTION SECTION (Giữ nguyên câu hỏi) ---
        responseStream.write(request, 12, questionLength);

        // --- 3. BUILD ANSWER SECTION (Nếu tìm thấy trong DB) ---
        if (resolvedIpOrDomain != null) {
            ByteBuffer answerHeader = ByteBuffer.allocate(12);
            answerHeader.putShort((short) 0xC00C); // Pointer trỏ về QNAME ở byte thứ 12
            answerHeader.putShort(qType);          // TYPE
            answerHeader.putShort((short) 1);      // CLASS = IN
            answerHeader.putInt(300);              // TTL = 300s

            if (qType == 1) { // Record A (IPv4)
                String[] ipParts = resolvedIpOrDomain.split("\\.");
                byte[] ipBytes = new byte[4];
                for (int i = 0; i < 4; i++) {
                    ipBytes[i] = (byte) Integer.parseInt(ipParts[i]);
                }
                answerHeader.putShort((short) 4); // RDLENGTH = 4 bytes
                responseStream.write(answerHeader.array());
                responseStream.write(ipBytes);
                System.out.println("    [✓] Tìm thấy kết quả: " + resolvedIpOrDomain);
            } else if (qType == 12) { // Record PTR (Tra cứu ngược)
                ByteArrayOutputStream ptrData = new ByteArrayOutputStream();
                String[] labels = resolvedIpOrDomain.split("\\.");
                for (String label : labels) {
                    ptrData.write(label.length());
                    ptrData.write(label.getBytes(StandardCharsets.UTF_8));
                }
                ptrData.write(0);
                byte[] ptrBytes = ptrData.toByteArray();

                answerHeader.putShort((short) ptrBytes.length); // RDLENGTH
                responseStream.write(answerHeader.array());
                responseStream.write(ptrBytes);
                System.out.println("    [✓] Tìm thấy tên miền ngược: " + resolvedIpOrDomain);
            }
        } else {
            System.out.println("    [X] Không tìm thấy tên miền này trong Database nội bộ.");
        }

        return responseStream.toByteArray();
    }

    private static String readDomainName(ByteBuffer buffer) {
        StringBuilder domain = new StringBuilder();
        while (true) {
            int length = buffer.get() & 0xFF;
            if (length == 0) break;
            byte[] label = new byte[length];
            buffer.get(label);
            domain.append(new String(label, StandardCharsets.UTF_8)).append(".");
        }
        if (domain.length() > 0) domain.setLength(domain.length() - 1);
        return domain.toString();
    }
}
