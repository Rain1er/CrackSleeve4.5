import dns.SleeveSecurity;
import java.io.*;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.nio.file.Files;


public class CrackSleeve {
    private static byte[] OriginKey = {-13,-114,-77,-47,-93,53,-78,82,-75,-117,-62,-84,-34,-127,-75,66};
    private static byte[] CustomizeKey = {-13,-114,-77,-47,-93,53,-78,82,-75,-117,-62,-84,-34,-127,-75,66};

    private String DecDir = "Resource/Decode/sleeve";
    private String EncDir = "Resource/Encode/sleeve";
    private String SleeveDir = "sleeve"; // 本地 sleeve 文件夹路径

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
        if (option.equals("decode")){
            CrackSleevedResource.Setup(OriginKey);
            Cracker.DecodeFile();
        } else if (option.equals("encode")){
            CrackSleevedResource.Setup(CustomizeKey);
            Cracker.EncodeFile();
        }
    }

    private void DecodeFile() throws IOException {
        // 创建输出目录
        File saveDir = new File(this.DecDir);
        if (!saveDir.isDirectory())
            saveDir.mkdirs();

        // 读取本地 sleeve 文件夹下的所有 DLL 文件
        File sleeveDir = new File(this.SleeveDir);
        if (!sleeveDir.isDirectory()) {
            System.out.println("[-] sleeve directory not found: " + sleeveDir.getAbsolutePath());
            System.exit(1);
        }

        File[] dllFiles = sleeveDir.listFiles((dir, name) -> name.toLowerCase().endsWith(".dll"));
        if (dllFiles == null || dllFiles.length == 0) {
            System.out.println("[-] No DLL files found in: " + sleeveDir.getAbsolutePath());
            System.exit(1);
        }

        for (File dllFile : dllFiles) {
            System.out.print("[+] Decoding sleeve/" + dllFile.getName() + "......");
            byte[] decBytes = CrackSleevedResource.DecodeResourceFromFile(dllFile);
            if (decBytes != null && decBytes.length > 0) {
                File outFile = new File(saveDir, dllFile.getName());
                writeFile(outFile, decBytes);
                System.out.println("Done. (" + decBytes.length + " bytes -> " + outFile.getPath() + ")");
            } else {
                System.out.println("Fail.");
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
            byte[] encBytes = CrackSleevedResource.EncodeResource(file);
            if (encBytes != null && encBytes.length > 0) {
                File outFile = new File(saveDir, file.getName());
                writeFile(outFile, encBytes);
                System.out.println("Done. (" + encBytes.length + " bytes -> " + outFile.getPath() + ")");
            } else {
                System.out.println("Fail.");
            }
        }
    }

    // ===== 纯 Java 原生文件读写，完全不依赖 CommonUtils =====

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

    /**
     * 直接从本地 File 读取原始字节并解密，完全不经过 CommonUtils
     */
    public static byte[] DecodeResourceFromFile(File file) {
        return singleton._DecodeResourceFromFile(file);
    }

    /**
     * 从本地 File 读取字节并加密
     */
    public static byte[] EncodeResource(File file) {
        return singleton._EncodeResource(file);
    }

    private byte[] _DecodeResourceFromFile(File file) {
        try {
            byte[] raw = CrackSleeve.readFile(file);
            if (raw.length > 0) {
                return this.data.decrypt(raw);
            } else {
                System.err.println("[-] File is empty: " + file.getPath());
            }
        } catch (IOException e) {
            System.err.println("[-] Failed to read: " + file.getPath());
            e.printStackTrace();
        }
        return new byte[0];
    }

    private byte[] _EncodeResource(File file) {
        try {
            byte[] raw = CrackSleeve.readFile(file);
            if (raw.length > 0) {
                return this.data.encrypt(raw);
            } else {
                System.err.println("[-] File is empty: " + file.getPath());
            }
        } catch (IOException e) {
            System.err.println("[-] Failed to read: " + file.getPath());
            e.printStackTrace();
        }
        return new byte[0];
    }
}