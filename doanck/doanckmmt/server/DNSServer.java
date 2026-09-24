package doanckmmt.server;

import java.io.*;
import java.net.*;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

public class DNSServer {

    private static final int PORT = 5354;
    private static final String UPSTREAM_DNS = "8.8.8.8"; // Google Public DNS
    private static final int UPSTREAM_PORT = 53;
    private static final String LOG_FILE = "dns_server.log";

    // 1. Database DNS Nội bộ
    private static final Map<String, String> localDnsTable = new HashMap<>();

    // 2. Bộ nhớ đệm Cache (Thread-safe)
    private static class CacheEntry {
        byte[] responseData;
        long expireTimeMs;

        CacheEntry(byte[] responseData, long ttlSeconds) {
            this.responseData = responseData;
            this.expireTimeMs = System.currentTimeMillis() + (ttlSeconds * 1000);
        }

        boolean isExpired() {
            return System.currentTimeMillis() > expireTimeMs;
        }
    }
    private static final Map<String, CacheEntry> cacheMap = new ConcurrentHashMap<>();

    // 3. Thống kê Metrics
    private static int totalRequests = 0;
    private static int localHits = 0;
    private static int cacheHits = 0;
    private static int forwardedRequests = 0;

    public static void main(String[] args) {
        initLocalDNSTable();

        System.out.println("=================================================================");
        System.out.println("   HỆ THỐNG DNS SERVER NÂNG CAO (FORWARDER + CACHING + LOGGING)  ");
        System.out.println("=================================================================");
        System.out.println("[+] Listening Port UDP      : " + PORT);
        System.out.println("[+] Upstream Forwarder DNS  : " + UPSTREAM_DNS + ":" + UPSTREAM_PORT);
        System.out.println("[+] Local Records Loaded    : " + localDnsTable.size());
        System.out.println("[+] Log File Active         : " + LOG_FILE);
        System.out.println("[+] Đang chờ kết nối từ Client...\n");

        logToFile("=== DNS SERVER STARTED ON PORT " + PORT + " ===");

        try (DatagramSocket socket = new DatagramSocket(PORT)) {
            byte[] receiveBuffer = new byte[1024];

            while (true) {
                DatagramPacket receivePacket = new DatagramPacket(receiveBuffer, receiveBuffer.length);
                socket.receive(receivePacket);

                totalRequests++;
                InetAddress clientAddress = receivePacket.getAddress();
                int clientPort = receivePacket.getPort();
                byte[] requestData = Arrays.copyOf(receivePacket.getData(), receivePacket.getLength());

                long startTime = System.currentTimeMillis();

                String domain = extractDomainName(requestData);
                int qType = extractQueryType(requestData);
                String cacheKey = domain.toLowerCase() + "_" + qType;

                System.out.println("-----------------------------------------------------------------");
                System.out.println("[# " + totalRequests + "] Query từ Client: " + clientAddress.getHostAddress() + ":" + clientPort);
                System.out.println("    + Domain   : [" + domain + "]");
                System.out.println("    + Record   : " + getRecordTypeName(qType) + " (Type " + qType + ")");

                byte[] responseData = null;
                String statusLog = "";

                // STRATEGY 1: Kiểm tra Database nội bộ
                if (localDnsTable.containsKey(domain.toLowerCase())) {
                    responseData = buildLocalResponse(requestData, domain, qType);
                    localHits++;
                    statusLog = "LOCAL DB HIT";
                    System.out.println("    [✓] Nguồn: " + statusLog + " -> " + localDnsTable.get(domain.toLowerCase()));
                }
                // STRATEGY 2: Kiểm tra Bộ nhớ đệm Cache
                else if (cacheMap.containsKey(cacheKey) && !cacheMap.get(cacheKey).isExpired()) {
                    byte[] cachedRaw = cacheMap.get(cacheKey).responseData;
                    responseData = syncTransactionId(cachedRaw, requestData);
                    cacheHits++;
                    statusLog = "CACHE HIT (0ms)";
                    System.out.println("    [⚡] Nguồn: " + statusLog);
                }
                // STRATEGY 3: Forward đệ quy lên Google DNS (8.8.8.8)
                else {
                    responseData = forwardToUpstream(requestData);
                    if (responseData != null) {
                        forwardedRequests++;
                        statusLog = "FORWARDED (Google DNS 8.8.8.8)";
                        cacheMap.put(cacheKey, new CacheEntry(responseData, 60)); // Cache trong 60 giây
                        System.out.println("    [🌐] Nguồn: " + statusLog + " (Đã lưu Cache 60s)");
                    } else {
                        statusLog = "ERROR / TIMEOUT";
                    }
                }

                // Gửi câu trả lời về cho Client
                if (responseData != null) {
                    DatagramPacket sendPacket = new DatagramPacket(responseData, responseData.length, clientAddress, clientPort);
                    socket.send(sendPacket);
                    long processTime = System.currentTimeMillis() - startTime;

                    String logMsg = String.format("CLIENT: %s:%d | DOMAIN: %s | TYPE: %s | STATUS: %s | TIME: %dms",
                            clientAddress.getHostAddress(), clientPort, domain, getRecordTypeName(qType), statusLog, processTime);
                    logToFile(logMsg);
                    System.out.println("    [=>] Đã phản hồi Client (" + processTime + " ms)");
                }

                printMetrics();
            }
        } catch (Exception e) {
            System.err.println("[-] Lỗi Fatal Server: " + e.getMessage());
            logToFile("FATAL ERROR: " + e.getMessage());
        }
    }

    private static void initLocalDNSTable() {
        localDnsTable.put("nhom14.local", "192.168.1.100");
        localDnsTable.put("mywebsite.com", "10.0.0.88");
        localDnsTable.put("100.1.168.192.in-addr.arpa", "nhom14.local");
    }

    private static byte[] forwardToUpstream(byte[] queryData) {
        try (DatagramSocket upstreamSocket = new DatagramSocket()) {
            upstreamSocket.setSoTimeout(3000);
            InetAddress googleAddr = InetAddress.getByName(UPSTREAM_DNS);
            DatagramPacket sendPacket = new DatagramPacket(queryData, queryData.length, googleAddr, UPSTREAM_PORT);
            upstreamSocket.send(sendPacket);

            byte[] receiveBuffer = new byte[1024];
            DatagramPacket receivePacket = new DatagramPacket(receiveBuffer, receiveBuffer.length);
            upstreamSocket.receive(receivePacket);

            return Arrays.copyOf(receivePacket.getData(), receivePacket.getLength());
        } catch (Exception e) {
            System.err.println("    [!] Lỗi Forward đệ quy: " + e.getMessage());
            return null;
        }
    }

    private static byte[] syncTransactionId(byte[] cachedResponse, byte[] newRequest) {
        byte[] copy = Arrays.copyOf(cachedResponse, cachedResponse.length);
        copy[0] = newRequest[0];
        copy[1] = newRequest[1];
        return copy;
    }

    private static byte[] buildLocalResponse(byte[] request, String domain, int qType) throws Exception {
        ByteBuffer buffer = ByteBuffer.wrap(request);
        short id = buffer.getShort();

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ByteBuffer header = ByteBuffer.allocate(12);
        header.putShort(id);
        header.putShort((short) 0x8180);
        header.putShort((short) 1);
        header.putShort((short) 1);
        header.putShort((short) 0);
        header.putShort((short) 0);
        out.write(header.array());

        int questionLen = request.length - 12;
        out.write(request, 12, questionLen);

        String ip = localDnsTable.get(domain.toLowerCase());
        ByteBuffer answerHeader = ByteBuffer.allocate(12);
        answerHeader.putShort((short) 0xC00C);
        answerHeader.putShort((short) qType);
        answerHeader.putShort((short) 1);
        answerHeader.putInt(300);
        answerHeader.putShort((short) 4);
        out.write(answerHeader.array());

        String[] parts = ip.split("\\.");
        for (String p : parts) {
            out.write((byte) Integer.parseInt(p));
        }

        return out.toByteArray();
    }

    private static String extractDomainName(byte[] request) {
        ByteBuffer buffer = ByteBuffer.wrap(request);
        buffer.position(12);
        StringBuilder domain = new StringBuilder();
        while (buffer.hasRemaining()) {
            int len = buffer.get() & 0xFF;
            if (len == 0) break;
            byte[] b = new byte[len];
            buffer.get(b);
            domain.append(new String(b, StandardCharsets.UTF_8)).append(".");
        }
        if (domain.length() > 0) domain.setLength(domain.length() - 1);
        return domain.toString();
    }

    private static int extractQueryType(byte[] request) {
        ByteBuffer buffer = ByteBuffer.wrap(request);
        buffer.position(12);
        while (buffer.hasRemaining()) {
            int len = buffer.get() & 0xFF;
            if (len == 0) break;
            buffer.position(buffer.position() + len);
        }
        return buffer.getShort() & 0xFFFF;
    }

    private static String getRecordTypeName(int type) {
        switch (type) {
            case 1: return "A (IPv4)";
            case 28: return "AAAA (IPv6)";
            case 5: return "CNAME";
            case 15: return "MX";
            case 16: return "TXT";
            case 12: return "PTR";
            default: return "TYPE_" + type;
        }
    }

    private static synchronized void logToFile(String msg) {
        try (FileWriter fw = new FileWriter(LOG_FILE, true);
             PrintWriter pw = new PrintWriter(fw)) {
            String time = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));
            pw.println("[" + time + "] " + msg);
        } catch (Exception ignored) {}
    }

    private static void printMetrics() {
        System.out.println("    -------------------------------------------------------------");
        System.out.println(String.format("    📊 THỐNG KÊ: Total: %d | Local: %d | Cache Hit: %d | Forwarded: %d",
                totalRequests, localHits, cacheHits, forwardedRequests));
        System.out.println("    -------------------------------------------------------------");
    }
}