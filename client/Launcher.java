import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;
import java.net.*;
import java.nio.file.*;
import java.security.*;
import java.util.Scanner;
import java.util.jar.Manifest;

/**
 * Jartix Launcher — стримит клиент с сервера, расшифровывает, запускает.
 */
public class Launcher {

    private static final String SERVER = System.getenv().getOrDefault("JARTIX_SERVER", "https://launcher-server-wl84.onrender.com");

    public static void main(String[] args) throws Exception {
        Scanner sc = new Scanner(System.in);
        System.out.println("========================================");
        System.out.println("          JARTIX LAUNCHER");
        System.out.println("========================================");
        System.out.println();

        // 1. Get HWID
        String hwid = getHWID();
        System.out.println("[HWID] " + hwid.substring(0, 16) + "...");

        // 2. Login
        System.out.print("Login: ");
        String username = sc.nextLine().trim();
        System.out.print("Password: ");
        String password = sc.nextLine().trim();

        String loginToken = login(username, password);
        if (loginToken == null) {
            System.out.println("[ERROR] Invalid credentials");
            waitForExit();
            return;
        }
        System.out.println("[AUTH] Login success");

        // 3. Activate key if needed
        System.out.print("Key (or Enter if already activated): ");
        String key = sc.nextLine().trim();
        if (!key.isEmpty()) {
            if (activateKey(loginToken, key, hwid)) {
                System.out.println("[KEY] Key activated!");
            } else {
                System.out.println("[KEY] Key already activated or error");
            }
        }

        // 4. Validate session
        String session = validateSession(loginToken, hwid);
        if (session == null) {
            System.out.println("[ERROR] No active subscription or HWID mismatch");
            waitForExit();
            return;
        }
        System.out.println("[SESSION] Subscription confirmed");

        // 5. Stream and decrypt client
        System.out.println("[CLIENT] Downloading client from server...");
        byte[] clientData = streamClient(session);
        if (clientData == null) {
            System.out.println("[ERROR] Client not found on server");
            waitForExit();
            return;
        }
        System.out.println("[CLIENT] Downloaded " + (clientData.length / 1024) + " KB (encrypted)");

        // 6. Decrypt in memory
        byte[] decrypted = decrypt(clientData);
        System.out.println("[CLIENT] Decrypted " + (decrypted.length / 1024) + " KB");

        // 7. Save to temp and launch as separate process
        System.out.println("[CLIENT] Starting client...");
        launchClient(decrypted);
    }

    static void waitForExit() {
        System.out.println("\nPress Enter to exit...");
        try { new Scanner(System.in).nextLine(); } catch (Exception ignored) {}
    }

    // ── HWID Generation ────────────────────────────────
    static String getHWID() {
        try {
            StringBuilder sb = new StringBuilder();
            Process p = Runtime.getRuntime().exec(new String[]{"wmic", "baseboard", "get", "serialnumber"});
            BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
            String line;
            while ((line = br.readLine()) != null) {
                line = line.trim();
                if (!line.isEmpty() && !line.equals("SerialNumber")) sb.append(line);
            }
            p = Runtime.getRuntime().exec(new String[]{"wmic", "cpu", "get", "ProcessorId"});
            br = new BufferedReader(new InputStreamReader(p.getInputStream()));
            while ((line = br.readLine()) != null) {
                line = line.trim();
                if (!line.isEmpty() && !line.equals("ProcessorId")) sb.append(line);
            }
            p = Runtime.getRuntime().exec(new String[]{"wmic", "diskdrive", "get", "serialnumber"});
            br = new BufferedReader(new InputStreamReader(p.getInputStream()));
            while ((line = br.readLine()) != null) {
                line = line.trim();
                if (!line.isEmpty() && !line.equals("SerialNumber")) { sb.append(line); break; }
            }
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(sb.toString().getBytes());
            StringBuilder hex = new StringBuilder();
            for (byte b : hash) hex.append(String.format("%02x", b));
            return hex.toString();
        } catch (Exception e) {
            String envName = System.getenv("COMPUTERNAME");
            return "fallback-" + (envName != null ? envName : "unknown");
        }
    }

    // ── API Calls ──────────────────────────────────────
    static String login(String username, String password) {
        try {
            String json = String.format("{\"username\":\"%s\",\"password\":\"%s\"}", username, password);
            String resp = post(SERVER + "/api/auth/login", json, null);
            if (resp == null) return null;
            int idx = resp.indexOf("\"token\":\"");
            if (idx < 0) return null;
            return resp.substring(idx + 9, resp.indexOf("\"", idx + 9));
        } catch (Exception e) { return null; }
    }

    static boolean activateKey(String token, String key, String hwid) {
        try {
            String json = String.format("{\"key\":\"%s\",\"hwid\":\"%s\"}", key, hwid);
            String resp = post(SERVER + "/api/launcher/activate", json, token);
            return resp != null && resp.contains("\"ok\":true");
        } catch (Exception e) { return false; }
    }

    static String validateSession(String token, String hwid) {
        try {
            String json = String.format("{\"hwid\":\"%s\"}", hwid);
            String resp = post(SERVER + "/api/launcher/validate", json, token);
            if (resp == null || !resp.contains("\"ok\":true")) return null;
            int idx = resp.indexOf("\"session\":\"");
            if (idx < 0) return null;
            return resp.substring(idx + 11, resp.indexOf("\"", idx + 11));
        } catch (Exception e) { return null; }
    }

    static byte[] streamClient(String session) {
        try {
            URL url = new URL(SERVER + "/api/launcher/client");
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");
            conn.setRequestProperty("X-Session", session);
            conn.setConnectTimeout(10000);
            conn.setReadTimeout(120000);
            if (conn.getResponseCode() != 200) return null;
            InputStream is = conn.getInputStream();
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            byte[] buf = new byte[8192];
            int n;
            while ((n = is.read(buf)) != -1) baos.write(buf, 0, n);
            return baos.toByteArray();
        } catch (Exception e) { return null; }
    }

    static String post(String urlStr, String json, String bearerToken) {
        try {
            URL url = new URL(urlStr);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json");
            if (bearerToken != null) conn.setRequestProperty("Authorization", "Bearer " + bearerToken);
            conn.setDoOutput(true);
            conn.getOutputStream().write(json.getBytes());
            BufferedReader br = new BufferedReader(new InputStreamReader(conn.getInputStream()));
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = br.readLine()) != null) sb.append(line);
            return sb.toString();
        } catch (Exception e) { return null; }
    }

    // ── Decrypt ────────────────────────────────────────
    static byte[] decrypt(byte[] data) throws Exception {
        byte[] iv = new byte[16];
        byte[] encrypted = new byte[data.length - 16];
        System.arraycopy(data, 0, iv, 0, 16);
        System.arraycopy(data, 16, encrypted, 0, encrypted.length);
        String keyHexEnv = System.getenv("ENCRYPTION_KEY");
        String keyHex = keyHexEnv != null ? keyHexEnv : "0000000000000000000000000000000000000000000000000000000000000000";
        byte[] key = hexToBytes(keyHex);
        SecretKeySpec secretKey = new SecretKeySpec(key, "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(iv));
        return cipher.doFinal(encrypted);
    }

    static byte[] hexToBytes(String hex) {
        byte[] bytes = new byte[hex.length() / 2];
        for (int i = 0; i < bytes.length; i++) {
            bytes[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
        }
        return bytes;
    }

    // ── Launch Client ──────────────────────────────────
    static void launchClient(byte[] jarData) throws Exception {
        // Save JAR to temp
        Path tempDir = Files.createTempDirectory("jartix");
        Path tempJar = tempDir.resolve("client.jar");
        Files.write(tempJar, jarData);

        // Try to read Main-Class from manifest
        String mainClass = null;
        try (InputStream is = Files.newInputStream(tempJar)) {
            Manifest manifest = new Manifest(is);
            mainClass = manifest.getMainAttributes().getValue("Main-Class");
        } catch (Exception ignored) {}

        // Build classpath
        String classpath = tempJar.toAbsolutePath().toString();

        // Build java command
        String javaHome = System.getProperty("java.home");
        String javaBin = javaHome + File.separator + "bin" + File.separator + "java";

        ProcessBuilder pb;
        if (mainClass != null && !mainClass.isEmpty()) {
            System.out.println("[CLIENT] Main class: " + mainClass);
            pb = new ProcessBuilder(javaBin, "-cp", classpath, mainClass);
        } else {
            System.out.println("[CLIENT] No Main-Class in manifest, using java -jar");
            pb = new ProcessBuilder(javaBin, "-jar", classpath);
        }

        pb.inheritIO();
        pb.directory(tempDir.toFile());

        System.out.println("[CLIENT] Launching...");
        Process process = pb.start();

        // Wait for client to start, then cleanup
        Thread cleanup = new Thread(() -> {
            try {
                process.waitFor();
            } catch (Exception ignored) {}
            try { Files.deleteIfExists(tempJar); } catch (Exception ignored) {}
            try { Files.deleteIfExists(tempDir); } catch (Exception ignored) {}
        });
        cleanup.setDaemon(true);
        cleanup.start();

        int exitCode = process.waitFor();
        System.out.println("[CLIENT] Client exited with code: " + exitCode);
        waitForExit();
    }
}
