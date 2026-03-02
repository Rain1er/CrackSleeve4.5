import dns.SleeveSecurity;
import java.io.*;
import java.net.URL;
import java.nio.file.Files;
import java.util.Enumeration;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;


public class CrackSleeve {
    private static byte[] OriginKey = {-13,-114,-77,-47,-93,53,-78,82,-75,-117,-62,-84,-34,-127,-75,66};
    private static byte[] CustomizeKey = {-13,-114,-77,-47,-93,53,-78,82,-75,-117,-62,-84,-34,-127,-75,66};

    private String DecDir = "Resource/Decode/sleeve";
    private String EncDir = "Resource/Encode/sleeve";

    public static void main(String[] args) throws IOException {
        if (args.length == 0 || args[0].equals("-h") || args[0].equals("--help")) {
            System.out.println("UseAge: CrackSleeve OPTION [key]");
            System.out.println("Options:");
            System.out.println("\tdecode\t\tDecode sleeve files");
            System.out.println("\tencode\t\tEncode sleeve files");
            System.exit(0);
        }
        String option = args[0];

        CrackSleeve Cracker = new CrackSleeve();
        if (option.equals("decode")) {
            CrackSleevedResource.Setup(OriginKey);
            Cracker.DecodeFile();
        } else if (option.equals("encode")) {
            CrackSleevedResource.Setup(CustomizeKey);
            Cracker.EncodeFile();
        }
    }

    private void DecodeFile() throws IOException {
        // 创建输出目录
        File saveDir = new File(this.DecDir);
        if (!saveDir.isDirectory())
            saveDir.mkdirs();

        // 定位 cobaltstrike.jar 路径（通过 ClassLoader 找到含 sleeve/ 的 jar）
        URL sleeveUrl = CrackSleeve.class.getClassLoader().getResource("sleeve");
        if (sleeveUrl == null) {
            System.out.println("[-] Cannot find 'sleeve' resource in classpath.");
            System.exit(1);
        }

        // 格式: jar:file:/path/to/cobaltstrike.jar!/sleeve
        String urlStr = sleeveUrl.toString();
        String jarPath = urlStr.substring("jar:file:".length(), urlStr.indexOf("!/"));

        System.out.println("[*] Reading from jar: " + jarPath);

        try (JarFile jarFile = new JarFile(new File(jarPath))) {
            Enumeration<JarEntry> entries = jarFile.entries();
            while (entries.hasMoreElements()) {
                JarEntry entry = entries.nextElement();
                String name = entry.getName();

                // 只处理 sleeve/ 下的 .dll 文件，跳过目录本身
                if (!name.startsWith("sleeve/") || entry.isDirectory())
                    continue;
                if (!name.toLowerCase().endsWith(".dll"))
                    continue;

                System.out.print("[+] Decoding " + name + "......");

                // 直接从 jar 流中读取原始字节，完全不经过 CommonUtils
                byte[] rawBytes = readJarEntry(jarFile, entry);
                if (rawBytes == null || rawBytes.length == 0) {
                    System.out.println("Fail. (empty)");
                    continue;
                }

                byte[] decBytes = CrackSleevedResource.Decrypt(rawBytes);
                if (decBytes != null && decBytes.length > 0) {
                    String fileName = name.substring(name.lastIndexOf('/') + 1);
                    File outFile = new File(saveDir, fileName);
                    writeFile(outFile, decBytes);
                    System.out.println("Done. (" + decBytes.length + " bytes -> " + outFile.getPath() + ")");
                } else {
                    System.out.println("Fail. (decrypt returned empty)");
                }
            }
        }
    }

    private void EncodeFile() throws IOException {
        // 创建输出目录
        File saveDir = new File(this.EncDir);
        if (!saveDir.isDirectory())
            saveDir.mkdirs();

        File decDir = new File(this.DecDir);
        File[] decFiles = decDir.listFiles();
        if (decFiles == null || decFiles.length == 0) {
            System.out.println("[-] There's no file to encode, please decode first.");
            System.exit(0);
        }

        for (File file : decFiles) {
            System.out.print("[+] Encoding " + file.getName() + "......");
            byte[] encBytes = CrackSleevedResource.Encrypt(file);
            if (encBytes != null && encBytes.length > 0) {
                File outFile = new File(saveDir, file.getName());
                writeFile(outFile, encBytes);
                System.out.println("Done. (" + encBytes.length + " bytes -> " + outFile.getPath() + ")");
            } else {
                System.out.println("Fail.");
            }
        }
    }

    // ===== 原生文件读写，完全不依赖 CommonUtils =====

    public static byte[] readJarEntry(JarFile jarFile, JarEntry entry) throws IOException {
        try (InputStream is = jarFile.getInputStream(entry);
             ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            byte[] buf = new byte[4096];
            int n;
            while ((n = is.read(buf)) != -1)
                baos.write(buf, 0, n);
            return baos.toByteArray();
        }
    }

    public static byte[] readFile(File file) throws IOException {
        return Files.readAllBytes(file.toPath());
    }

    public static void writeFile(File file, byte[] data) throws IOException {
        file.getParentFile().mkdirs();
        Files.write(file.toPath(), data);
    }
}


class CrackSleevedResource {
    private static CrackSleevedResource singleton;
    private SleeveSecurity data = new SleeveSecurity();

    public static void Setup(byte[] key) {
        singleton = new CrackSleevedResource(key);
    }

    private CrackSleevedResource(byte[] key) {
        this.data.registerKey(key);
    }

    /** 解密原始字节 */
    public static byte[] Decrypt(byte[] raw) {
        return singleton._decrypt(raw);
    }

    /** 从文件读取并加密 */
    public static byte[] Encrypt(File file) {
        return singleton._encrypt(file);
    }

    private byte[] _decrypt(byte[] raw) {
        try {
            return this.data.decrypt(raw);
        } catch (Exception e) {
            System.err.println("[-] Decrypt error: " + e.getMessage());
            return new byte[0];
        }
    }

    private byte[] _encrypt(File file) {
        try {
            byte[] raw = CrackSleeve.readFile(file);
            if (raw.length > 0)
                return this.data.encrypt(raw);
        } catch (IOException e) {
            System.err.println("[-] Failed to read: " + file.getPath());
            e.printStackTrace();
        }
        return new byte[0];
    }
}
