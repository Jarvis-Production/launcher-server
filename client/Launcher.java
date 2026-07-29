import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;
import java.net.*;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.*;
import java.security.*;
import java.util.*;
import java.util.jar.Manifest;

public class Launcher {
    private static final String SERVER = "https://launcher-server-wl84.onrender.com";
    private static final String CLIENT_URL = "https://raw.githubusercontent.com/Jarvis-Production/client/main/jartix-1.1.03.jar";
    private static final String MC_VERSION = "1.21.11";
    private static final String FABRIC_LOADER = "0.18.4";
    private static final String FABRIC_API = "0.141.2+1.21.11";
    private static final Path HOME = Path.of(System.getProperty("user.home"), ".jartix");
    private static final Path MC_DIR = HOME.resolve("minecraft");
    private static final Path MODS_DIR = MC_DIR.resolve("mods");
    private static final Path FABRIC_DIR = MC_DIR.resolve("fabric");

    public static void main(String[] args) throws Exception {
        Scanner sc = new Scanner(System.in);
        System.out.print("Login: ");
        String username = sc.nextLine().trim();
        System.out.print("Password: ");
        String password = sc.nextLine().trim();

        String token = login(username, password);
        if (token == null) { System.out.println("Invalid credentials"); waitAndExit(); return; }

        System.out.print("Key: ");
        String key = sc.nextLine().trim();
        if (!key.isEmpty()) activateKey(token, key, getHWID());

        String session = validateSession(token, getHWID());
        if (session == null) { System.out.println("No subscription"); waitAndExit(); return; }

        Files.createDirectories(MODS_DIR);
        Files.createDirectories(FABRIC_DIR);

        downloadClient();
        downloadMinecraft();
        downloadFabric();
        downloadFabricApi();
        downloadAssets();

        System.out.println("\nLaunching JARTIX BETA...");
        launch(username);
    }

    // ════ SETUP ════
    static void downloadClient() throws Exception {
        Path f = MODS_DIR.resolve("jartix.jar");
        if (Files.exists(f)) return;
        Files.write(f, downloadUrl(CLIENT_URL));
    }

    static void downloadMinecraft() throws Exception {
        Path clientJar = MC_DIR.resolve("versions").resolve(MC_VERSION).resolve(MC_VERSION + ".jar");
        if (Files.exists(clientJar)) return;

        String manifest = downloadStr("https://launchermeta.mojang.com/mc/game/version_manifest_v2.json");
        int idx = manifest.indexOf("\"" + MC_VERSION + "\"");
        int us = manifest.indexOf("\"url\":", idx);
        int vs = manifest.indexOf("\"", us + 6) + 1;
        String versionUrl = manifest.substring(vs, manifest.indexOf("\"", vs));
        String verJson = downloadStr(versionUrl);

        int ci = verJson.indexOf("\"client\":");
        int cu = verJson.indexOf("\"url\":", ci);
        int cvs = verJson.indexOf("\"", cu + 6) + 1;
        String clientUrl = verJson.substring(cvs, verJson.indexOf("\"", cvs));

        Path versionDir = MC_DIR.resolve("versions").resolve(MC_VERSION);
        Files.createDirectories(versionDir);
        Files.write(clientJar, downloadUrl(clientUrl));
        Files.write(versionDir.resolve(MC_VERSION + ".json"), verJson.getBytes());

        // Download MC libraries
        Path libsDir = MC_DIR.resolve("libraries");
        Files.createDirectories(libsDir);
        int pos = verJson.indexOf("[", verJson.indexOf("\"libraries\"")) + 1;
        while (pos < verJson.length()) {
            int objStart = verJson.indexOf('{', pos);
            if (objStart < 0) break;
            int objEnd = findBrace(verJson, objStart);
            if (objEnd < 0) break;
            String obj = verJson.substring(objStart, objEnd + 1);
            pos = objEnd + 1;

            int ni = obj.indexOf("\"name\":");
            if (ni < 0) continue;
            int ns = obj.indexOf("\"", ni + 7) + 1;
            String name = obj.substring(ns, obj.indexOf("\"", ns));

            int ui = obj.indexOf("\"url\":");
            String base = "https://libraries.minecraft.net/";
            if (ui >= 0) {
                int us2 = obj.indexOf("\"", ui + 6) + 1;
                base = obj.substring(us2, obj.indexOf("\"", us2));
                if (!base.endsWith("/")) base += "/";
            }

            String[] p = name.split(":");
            if (p.length >= 3) {
                String g = p[0].replace('.', '/'), a = p[1], v = p[2];
                String c = p.length > 3 ? "-" + p[3] : "";
                String url = base + g + "/" + a + "/" + v + "/" + a + "-" + v + c + ".jar";
                Path dir = libsDir.resolve(g + "/" + a + "/" + v);
                Files.createDirectories(dir);
                Path f = dir.resolve(a + "-" + v + c + ".jar");
                if (!Files.exists(f)) { try { Files.write(f, downloadUrl(url)); } catch (Exception e) {} }
            }
        }
    }

    static void downloadFabric() throws Exception {
        if (Files.exists(FABRIC_DIR.resolve(".ok"))) return;
        String profile = downloadStr("https://meta.fabricmc.net/v2/versions/loader/" + MC_VERSION + "/" + FABRIC_LOADER + "/profile/json");
        Files.createDirectories(FABRIC_DIR);
        int i = 0;
        while (true) {
            int ni = profile.indexOf("\"name\":", i);
            if (ni < 0) break;
            int ns = profile.indexOf("\"", ni + 7) + 1;
            String name = profile.substring(ns, profile.indexOf("\"", ns));
            i = ns;

            int ui = profile.indexOf("\"url\":", ni);
            String base = "https://maven.fabricmc.net/";
            if (ui > 0 && ui < ns + 200) {
                int us2 = profile.indexOf("\"", ui + 6) + 1;
                base = profile.substring(us2, profile.indexOf("\"", us2));
                if (!base.endsWith("/")) base += "/";
            }

            String[] p = name.split(":");
            if (p.length >= 3) {
                String g = p[0].replace('.', '/'), a = p[1], v = p[2];
                String url = base + g + "/" + a + "/" + v + "/" + a + "-" + v + ".jar";
                Path f = FABRIC_DIR.resolve(a + "-" + v + ".jar");
                if (!Files.exists(f)) { try { Files.write(f, downloadUrl(url)); } catch (Exception e) {} }
            }
        }
        Files.writeString(FABRIC_DIR.resolve(".ok"), "ok");
    }

    static void downloadFabricApi() throws Exception {
        Path f = MODS_DIR.resolve("fabric-api-" + FABRIC_API + ".jar");
        if (Files.exists(f)) return;
        try { Files.write(f, downloadUrl("https://maven.fabricmc.net/net/fabricmc/fabric-api/fabric-api/" + FABRIC_API + "/fabric-api-" + FABRIC_API + ".jar")); } catch (Exception e) {}
    }

    static void downloadAssets() throws Exception {
        Path indexFile = MC_DIR.resolve("assets").resolve("indexes").resolve("29.json");
        if (Files.exists(indexFile)) {
            // Check if all assets exist
            String json = Files.readString(indexFile);
            if (json.contains("\"objects\"")) {
                // Assets index exists, check a sample
                Path objectsDir = MC_DIR.resolve("assets").resolve("objects");
                if (Files.exists(objectsDir) && Files.list(objectsDir).findAny().isPresent()) return;
            }
        }

        Files.createDirectories(MC_DIR.resolve("assets").resolve("indexes"));
        Files.createDirectories(MC_DIR.resolve("assets").resolve("objects"));

        // Get asset index from version JSON
        Path versionJson = MC_DIR.resolve("versions").resolve(MC_VERSION).resolve(MC_VERSION + ".json");
        String verJson = Files.readString(versionJson);
        int aiIdx = verJson.indexOf("\"assetIndex\":");
        int aiUrlStart = verJson.indexOf("\"url\":", aiIdx);
        int aiUrlVs = verJson.indexOf("\"", aiUrlStart + 6) + 1;
        String aiUrl = verJson.substring(aiUrlVs, verJson.indexOf("\"", aiUrlVs));

        String aiJson = downloadStr(aiUrl);
        Files.writeString(indexFile, aiJson);

        // Parse and download
        String objectsDir = MC_DIR.resolve("assets").resolve("objects").toString();
        int pos = 0;
        int count = 0;
        while (true) {
            int hi = aiJson.indexOf("\"hash\":", pos);
            if (hi < 0) break;
            int hs = aiJson.indexOf("\"", hi + 7) + 1;
            String hash = aiJson.substring(hs, aiJson.indexOf("\"", hs));
            pos = hs;

            String subdir = hash.substring(0, 2);
            String dest = objectsDir + "\\" + subdir + "\\" + hash;
            if (!Files.exists(Path.of(dest))) {
                Files.createDirectories(Path.of(objectsDir + "\\" + subdir));
                try {
                    Files.write(Path.of(dest), downloadUrl("https://resources.download.minecraft.net/" + subdir + "/" + hash));
                    count++;
                } catch (Exception e) {}
            }
        }
    }

    // ════ LAUNCH ════
    static void launch(String username) throws Exception {
        Path clientJar = MC_DIR.resolve("versions").resolve(MC_VERSION).resolve(MC_VERSION + ".jar");
        String javaBin = findJava();
        if (javaBin == null) { System.out.println("Java 21+ not found"); waitAndExit(); return; }

        String profile = downloadStr("https://meta.fabricmc.net/v2/versions/loader/" + MC_VERSION + "/" + FABRIC_LOADER + "/profile/json");
        int mcIdx = profile.indexOf("\"mainClass\"");
        int mcs = profile.indexOf("\"", profile.indexOf(":", mcIdx) + 1) + 1;
        String mainClass = profile.substring(mcs, profile.indexOf("\"", mcs));

        StringBuilder cp = new StringBuilder(clientJar.toAbsolutePath().toString());
        Files.list(FABRIC_DIR).filter(p -> p.toString().endsWith(".jar")).forEach(p -> cp.append(File.pathSeparator).append(p.toAbsolutePath()));
        Files.list(MODS_DIR).filter(p -> p.toString().endsWith(".jar")).forEach(p -> cp.append(File.pathSeparator).append(p.toAbsolutePath()));
        Path libsDir = MC_DIR.resolve("libraries");
        if (Files.exists(libsDir)) Files.walk(libsDir).filter(p -> p.toString().endsWith(".jar")).forEach(p -> cp.append(File.pathSeparator).append(p.toAbsolutePath()));

        List<String> cmd = List.of(
            javaBin, "-Xmx2G", "-Xms1G", "-cp", cp.toString(), mainClass,
            "--username", username, "--version", MC_VERSION,
            "--gameDir", MC_DIR.toAbsolutePath().toString(),
            "--assetsDir", MC_DIR.resolve("assets").toAbsolutePath().toString(),
            "--assetIndex", "29",
            "--uuid", UUID.randomUUID().toString().replace("-", ""),
            "--accessToken", "0", "--userType", "mojang"
        );

        Process p = new ProcessBuilder(cmd).directory(MC_DIR.toFile()).inheritIO().start();
        Runtime.getRuntime().addShutdownHook(new Thread(() -> { if (p.isAlive()) p.destroyForcibly(); }));
        p.waitFor();
    }

    // ════ HWID ════
    static String getHWID() {
        try {
            StringBuilder sb = new StringBuilder();
            for (String[] cmd : new String[][]{{"wmic","baseboard","get","serialnumber"},{"wmic","cpu","get","ProcessorId"},{"wmic","diskdrive","get","serialnumber"}}) {
                Process p = Runtime.getRuntime().exec(cmd);
                BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
                String l; while ((l = br.readLine()) != null) { l = l.trim(); if (!l.isEmpty() && !l.equals("SerialNumber") && !l.equals("ProcessorId")) { sb.append(l); if (cmd[1].equals("diskdrive")) break; } }
            }
            byte[] h = MessageDigest.getInstance("SHA-256").digest(sb.toString().getBytes());
            StringBuilder hex = new StringBuilder(); for (byte b : h) hex.append(String.format("%02x", b));
            return hex.toString();
        } catch (Exception e) { String n = System.getenv("COMPUTERNAME"); return "fb-" + (n != null ? n : "x"); }
    }

    // ════ API ════
    static String login(String u, String p) { try { HttpResponse<String> r = post(SERVER + "/api/auth/login", String.format("{\"username\":\"%s\",\"password\":\"%s\"}", u, p), null); int i = r.body().indexOf("\"token\":\""); return i >= 0 ? r.body().substring(i + 9, r.body().indexOf("\"", i + 9)) : null; } catch (Exception e) { return null; } }
    static boolean activateKey(String t, String k, String h) { try { HttpResponse<String> r = post(SERVER + "/api/launcher/activate", String.format("{\"key\":\"%s\",\"hwid\":\"%s\"}", k, h), t); return r.statusCode() == 200 && r.body().contains("\"ok\":true"); } catch (Exception e) { return false; } }
    static String validateSession(String t, String h) { try { HttpResponse<String> r = post(SERVER + "/api/launcher/validate", String.format("{\"hwid\":\"%s\"}", h), t); if (r.statusCode() != 200 || !r.body().contains("\"ok\":true")) return null; int i = r.body().indexOf("\"session\":\""); return i >= 0 ? r.body().substring(i + 11, r.body().indexOf("\"", i + 11)) : null; } catch (Exception e) { return null; } }
    static HttpResponse<String> post(String url, String json, String token) throws Exception { var b = HttpRequest.newBuilder().uri(URI.create(url)).header("Content-Type", "application/json").POST(HttpRequest.BodyPublishers.ofString(json)); if (token != null) b.header("Authorization", "Bearer " + token); return HttpClient.newHttpClient().send(b.build(), HttpResponse.BodyHandlers.ofString()); }

    // ════ DOWNLOAD ════
    static byte[] downloadUrl(String url) throws Exception { HttpClient c = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.ALWAYS).build(); HttpResponse<byte[]> r = c.send(HttpRequest.newBuilder().uri(URI.create(url)).GET().build(), HttpResponse.BodyHandlers.ofByteArray()); if (r.statusCode() != 200) throw new IOException("HTTP " + r.statusCode()); return r.body(); }
    static String downloadStr(String url) throws Exception { HttpClient c = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.ALWAYS).build(); HttpResponse<String> r = c.send(HttpRequest.newBuilder().uri(URI.create(url)).GET().build(), HttpResponse.BodyHandlers.ofString()); if (r.statusCode() != 200) throw new IOException("HTTP " + r.statusCode()); return r.body(); }

    // ════ JAVA ════
    static String findJava() { String e = System.getenv("JAVA_HOME"); if (e != null) { String b = e + "\\bin\\java.exe"; if (Files.exists(Path.of(b))) return b; } String path = System.getenv("PATH"); if (path != null) for (String d : path.split(File.pathSeparator)) { String b = d + "\\java.exe"; if (Files.exists(Path.of(b))) return b; } for (int v = 25; v >= 21; v--) { String b = "C:\\Program Files\\Java\\jdk-" + v + "\\bin\\java.exe"; if (Files.exists(Path.of(b))) return b; } return null; }

    static int findBrace(String s, int start) { int d = 0; for (int i = start; i < s.length(); i++) { if (s.charAt(i) == '{') d++; if (s.charAt(i) == '}') { d--; if (d == 0) return i; } } return -1; }
    static void waitAndExit() { System.out.println("\nPress Enter..."); try { new Scanner(System.in).nextLine(); } catch (Exception e) {} }
}
