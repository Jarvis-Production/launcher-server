import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;
import java.net.*;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.*;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.jar.Attributes;
import java.util.jar.Manifest;

/**
 * Jartix Launcher — всё из памяти. Ни одного файла на диске.
 */
public class Launcher {

    private static final String SERVER = System.getenv().getOrDefault("JARTIX_SERVER", "https://launcher-server-wl84.onrender.com");

    public static void main(String[] args) throws Exception {
        System.out.println("========================================");
        System.out.println("          JARTIX LAUNCHER");
        System.out.println("========================================");
        System.out.println();

        String hwid = getHWID();
        System.out.println("[HWID] " + hwid.substring(0, 16) + "...");

        Scanner sc = new Scanner(System.in);
        System.out.print("Login: ");
        String username = sc.nextLine().trim();
        System.out.print("Password: ");
        String password = sc.nextLine().trim();

        String loginToken = login(username, password);
        if (loginToken == null) {
            System.out.println("[ERROR] Invalid credentials");
            waitAndExit();
            return;
        }
        System.out.println("[AUTH] Login success");

        System.out.print("Key (or Enter if already activated): ");
        String key = sc.nextLine().trim();
        if (!key.isEmpty()) {
            if (activateKey(loginToken, key, hwid)) {
                System.out.println("[KEY] Key activated!");
            } else {
                System.out.println("[KEY] Key already activated or error");
            }
        }

        String session = validateSession(loginToken, hwid);
        if (session == null) {
            System.out.println("[ERROR] No active subscription or HWID mismatch");
            waitAndExit();
            return;
        }
        System.out.println("[SESSION] Subscription confirmed");

        System.out.println("[CLIENT] Downloading client from server...");
        byte[] clientData = streamClient(session);
        if (clientData == null) {
            System.out.println("[ERROR] Client not found on server");
            waitAndExit();
            return;
        }
        System.out.println("[CLIENT] Downloaded " + (clientData.length / 1024) + " KB (encrypted)");

        byte[] decrypted = decrypt(clientData);
        System.out.println("[CLIENT] Decrypted " + (decrypted.length / 1024) + " KB");
        System.out.println("[CLIENT] Loading from memory...");

        launchFromMemory(decrypted);
    }

    // ══════════════════════════════════════════════════════
    // LOADING ENTIRELY FROM MEMORY — NO FILES ON DISK
    // ══════════════════════════════════════════════════════

    static void launchFromMemory(byte[] jarBytes) throws Exception {
        // Parse JAR: read all class entries into memory
        java.util.jar.JarInputStream jis = new java.util.jar.JarInputStream(new ByteArrayInputStream(jarBytes));
        Manifest manifest = jis.getManifest();
        Map<String, byte[]> classes = new ConcurrentHashMap<>();

        java.util.jar.JarEntry entry;
        while ((entry = jis.getNextJarEntry()) != null) {
            if (entry.isDirectory()) continue;
            String name = entry.getName();
            if (name.endsWith(".class")) {
                ByteArrayOutputStream baos = new ByteArrayOutputStream();
                byte[] buf = new byte[4096];
                int n;
                while ((n = jis.read(buf)) != -1) baos.write(buf, 0, n);
                classes.put(name, baos.toByteArray());
            }
        }
        jis.close();

        System.out.println("[CLIENT] Loaded " + classes.size() + " classes into memory");

        // Find Main-Class
        String mainClass = null;
        if (manifest != null) {
            Attributes attrs = manifest.getMainAttributes();
            if (attrs != null) mainClass = attrs.getValue("Main-Class");
        }

        // Create classloader from memory
        MemoryClassLoader loader = new MemoryClassLoader(classes, Launcher.class.getClassLoader());

        if (mainClass != null && !mainClass.isEmpty()) {
            System.out.println("[CLIENT] Main class: " + mainClass);
            System.out.println("[CLIENT] Launching from memory...");
            Class<?> clazz = loader.loadClass(mainClass);
            java.lang.reflect.Method mainMethod = clazz.getMethod("main", String[].class);
            mainMethod.invoke(null, (Object) new String[]{});
        } else {
            System.out.println("[CLIENT] No Main-Class found, trying common names...");
            String[] candidates = {"net.fabricmc.loader.impl.launch.knot.KnotClient", "net.minecraft.client.main.Main", "Main", "ClientMain", "com.jartix.Client"};
            for (String name : candidates) {
                try {
                    Class<?> clazz = loader.loadClass(name);
                    java.lang.reflect.Method mainMethod = clazz.getMethod("main", String[].class);
                    System.out.println("[CLIENT] Found: " + name);
                    mainMethod.invoke(null, (Object) new String[]{});
                    return;
                } catch (ClassNotFoundException ignored) {}
            }
            System.out.println("[ERROR] Could not find main class in JAR");
            waitAndExit();
        }
    }

    /**
     * Custom classloader that loads .class files from byte arrays in memory.
     * No temp files, no disk writes.
     */
    static class MemoryClassLoader extends ClassLoader {
        private final Map<String, byte[]> classBytes;

        MemoryClassLoader(Map<String, byte[]> classBytes, ClassLoader parent) {
            super(parent);
            this.classBytes = classBytes;
        }

        @Override
        protected Class<?> findClass(String name) throws ClassNotFoundException {
            String path = name.replace('.', '/') + ".class";
            byte[] bytes = classBytes.get(path);
            if (bytes == null) throw new ClassNotFoundException(name);
            return defineClass(name, bytes, 0, bytes.length);
        }

        @Override
        protected URL findResource(String name) {
            return null;
        }

        @Override
        public URL getResource(String name) {
            return null;
        }

        @Override
        public InputStream getResourceAsStream(String name) {
            byte[] bytes = classBytes.get(name);
            if (bytes != null) return new ByteArrayInputStream(bytes);
            return null;
        }
    }

    // ══════════════════════════════════════════════════════
    // HWID
    // ══════════════════════════════════════════════════════

    static String getHWID() {
        try {
            StringBuilder sb = new StringBuilder();
            Process p = Runtime.getRuntime().exec(new String[]{"wmic", "baseboard", "get", "serialnumber"});
            BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
            String line;
            while ((line = br.readLine()) != null) { line = line.trim(); if (!line.isEmpty() && !line.equals("SerialNumber")) sb.append(line); }
            p = Runtime.getRuntime().exec(new String[]{"wmic", "cpu", "get", "ProcessorId"});
            br = new BufferedReader(new InputStreamReader(p.getInputStream()));
            while ((line = br.readLine()) != null) { line = line.trim(); if (!line.isEmpty() && !line.equals("ProcessorId")) sb.append(line); }
            p = Runtime.getRuntime().exec(new String[]{"wmic", "diskdrive", "get", "serialnumber"});
            br = new BufferedReader(new InputStreamReader(p.getInputStream()));
            while ((line = br.readLine()) != null) { line = line.trim(); if (!line.isEmpty() && !line.equals("SerialNumber")) { sb.append(line); break; } }
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

    // ══════════════════════════════════════════════════════
    // API
    // ══════════════════════════════════════════════════════

    static String login(String username, String password) {
        try {
            HttpClient client = HttpClient.newHttpClient();
            String json = String.format("{\"username\":\"%s\",\"password\":\"%s\"}", username, password);
            HttpRequest req = HttpRequest.newBuilder().uri(URI.create(SERVER + "/api/auth/login"))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(json)).build();
            HttpResponse<String> resp = client.send(req, HttpResponse.BodyHandlers.ofString());
            if (resp.statusCode() != 200) return null;
            String body = resp.body();
            int idx = body.indexOf("\"token\":\"");
            if (idx < 0) return null;
            return body.substring(idx + 9, body.indexOf("\"", idx + 9));
        } catch (Exception e) { return null; }
    }

    static boolean activateKey(String token, String key, String hwid) {
        try {
            HttpClient client = HttpClient.newHttpClient();
            String json = String.format("{\"key\":\"%s\",\"hwid\":\"%s\"}", key, hwid);
            HttpRequest req = HttpRequest.newBuilder().uri(URI.create(SERVER + "/api/launcher/activate"))
                    .header("Content-Type", "application/json")
                    .header("Authorization", "Bearer " + token)
                    .POST(HttpRequest.BodyPublishers.ofString(json)).build();
            HttpResponse<String> resp = client.send(req, HttpResponse.BodyHandlers.ofString());
            return resp.statusCode() == 200 && resp.body().contains("\"ok\":true");
        } catch (Exception e) { return false; }
    }

    static String validateSession(String token, String hwid) {
        try {
            HttpClient client = HttpClient.newHttpClient();
            String json = String.format("{\"hwid\":\"%s\"}", hwid);
            HttpRequest req = HttpRequest.newBuilder().uri(URI.create(SERVER + "/api/launcher/validate"))
                    .header("Content-Type", "application/json")
                    .header("Authorization", "Bearer " + token)
                    .POST(HttpRequest.BodyPublishers.ofString(json)).build();
            HttpResponse<String> resp = client.send(req, HttpResponse.BodyHandlers.ofString());
            if (resp.statusCode() != 200 || !resp.body().contains("\"ok\":true")) return null;
            String body = resp.body();
            int idx = body.indexOf("\"session\":\"");
            if (idx < 0) return null;
            return body.substring(idx + 11, body.indexOf("\"", idx + 11));
        } catch (Exception e) { return null; }
    }

    static byte[] streamClient(String session) {
        try {
            HttpClient client = HttpClient.newHttpClient();
            HttpRequest req = HttpRequest.newBuilder().uri(URI.create(SERVER + "/api/launcher/client"))
                    .header("X-Session", session)
                    .GET().build();
            HttpResponse<byte[]> resp = client.send(req, HttpResponse.BodyHandlers.ofByteArray());
            if (resp.statusCode() != 200) return null;
            return resp.body();
        } catch (Exception e) { return null; }
    }

    // ══════════════════════════════════════════════════════
    // DECRYPT
    // ══════════════════════════════════════════════════════

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

    static void waitAndExit() {
        System.out.println("\nPress Enter to exit...");
        try { new Scanner(System.in).nextLine(); } catch (Exception ignored) {}
    }
}
