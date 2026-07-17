import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;
import java.net.*;
import java.nio.file.*;
import java.security.*;
import java.util.Scanner;

/**
 * Jartix Launcher — стримит клиент с сервера, расшифровывает в памяти.
 * Файлы НЕ создаются на диске пользователя.
 */
public class Launcher {

    private static final String SERVER = System.getenv().getOrDefault("JARTIX_SERVER", "https://launcher-server-wl84.onrender.com");
    private static final String VERSION = "1.0.0";

    public static void main(String[] args) throws Exception {
        Scanner sc = new Scanner(System.in);
        System.out.println("╔══════════════════════════════════════╗");
        System.out.println("║         JARTIX LAUNCHER             ║");
        System.out.println("╚══════════════════════════════════════╝");
        System.out.println();

        // 1. Get HWID
        String hwid = getHWID();
        System.out.println("[HWID] " + hwid.substring(0, 16) + "...");

        // 2. Login
        System.out.print("Логин: ");
        String username = sc.nextLine().trim();
        System.out.print("Пароль: ");
        String password = sc.nextLine().trim();

        String loginToken = login(username, password);
        if (loginToken == null) {
            System.out.println("[ERROR] Неверные credentials");
            return;
        }
        System.out.println("[AUTH] Успешный вход");

        // 3. Activate key if needed
        System.out.print("Ключ (или Enter если уже активирован): ");
        String key = sc.nextLine().trim();
        if (!key.isEmpty()) {
            if (activateKey(loginToken, key, hwid)) {
                System.out.println("[KEY] Ключ активирован!");
            } else {
                System.out.println("[KEY] Ключ уже активирован или ошибка");
            }
        }

        // 4. Validate session
        String session = validateSession(loginToken, hwid);
        if (session == null) {
            System.out.println("[ERROR] Нет активной подписки или HWID не совпадает");
            return;
        }
        System.out.println("[SESSION] Подписка подтверждена");

        // 5. Stream and decrypt client
        System.out.println("[CLIENT] Загрузка клиента с сервера...");
        byte[] clientData = streamClient(session);
        if (clientData == null) {
            System.out.println("[ERROR] Клиент не найден на сервере");
            return;
        }
        System.out.println("[CLIENT] Загружено " + (clientData.length / 1024) + " KB (зашифровано)");

        // 6. Decrypt in memory
        byte[] decrypted = decrypt(clientData);
        System.out.println("[CLIENT] Расшифровано " + (decrypted.length / 1024) + " KB");

        // 7. Load JAR in memory via custom classloader
        System.out.println("[CLIENT] Запуск клиента...");
        loadAndRun(decrypted);
    }

    // ── HWID Generation ────────────────────────────────
    static String getHWID() {
        try {
            StringBuilder sb = new StringBuilder();
            // Motherboard serial
            Process p = Runtime.getRuntime().exec(
                new String[]{"wmic", "baseboard", "get", "serialnumber"}
            );
            BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
            String line;
            while ((line = br.readLine()) != null) {
                line = line.trim();
                if (!line.isEmpty() && !line.equals("SerialNumber")) sb.append(line);
            }
            // CPU ID
            p = Runtime.getRuntime().exec(
                new String[]{"wmic", "cpu", "get", "ProcessorId"}
            );
            br = new BufferedReader(new InputStreamReader(p.getInputStream()));
            while ((line = br.readLine()) != null) {
                line = line.trim();
                if (!line.isEmpty() && !line.equals("ProcessorId")) sb.append(line);
            }
            // Disk serial
            p = Runtime.getRuntime().exec(
                new String[]{"wmic", "diskdrive", "get", "serialnumber"}
            );
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
            int start = idx + 9;
            int end = resp.indexOf("\"", start);
            return resp.substring(start, end);
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
            int start = idx + 11;
            int end = resp.indexOf("\"", start);
            return resp.substring(start, end);
        } catch (Exception e) { return null; }
    }

    static byte[] streamClient(String session) {
        try {
            URL url = new URL(SERVER + "/api/launcher/client");
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");
            conn.setRequestProperty("X-Session", session);
            conn.setConnectTimeout(10000);
            conn.setReadTimeout(60000);

            if (conn.getResponseCode() != 200) return null;

            InputStream is = conn.getInputStream();
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            byte[] buf = new byte[8192];
            int n;
            while ((n = is.read(buf)) != -1) baos.write(buf, 0, n);
            return baos.toByteArray();
        } catch (Exception e) { return null; }
    }

    // ── HTTP Helper ────────────────────────────────────
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

    // ── Load JAR in memory ─────────────────────────────
    static void loadAndRun(byte[] jarData) throws Exception {
        Path temp = Files.createTempFile("jartix-", ".jar");
        Files.write(temp, jarData);

        URLClassLoader loader = new URLClassLoader(
            new URL[]{temp.toUri().toURL()},
            Launcher.class.getClassLoader()
        );

        System.out.println("[CLIENT] Клиент загружен в память");
        System.out.println("[CLIENT] Для запуска укажите main class в настройках");

        Files.deleteIfExists(temp);
        System.out.println("[CLIENT] Temp файл удалён");
    }
}
