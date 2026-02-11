import java.io.*;
import java.nio.*;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.text.DecimalFormat;
import java.util.*;

public class ByteArsenal {

    public static void main(String[] args) throws Exception {
        if (args.length < 2) {
            usage();
            return;
        }

        String cmd = args[0].toLowerCase(Locale.ROOT);
        Path file = Paths.get(args[1]);

        if (!Files.isRegularFile(file)) {
            System.err.println("File not found: " + file.toAbsolutePath());
            System.exit(2);
        }

        Map<String, String> opt = parseOpts(args, 2);

        switch (cmd) {
            case "hash" -> cmdHash(file, opt, args, 2);
            case "hexdump" -> cmdHexdump(file, opt);
            case "strings" -> cmdStrings(file, opt);
            case "entropy" -> cmdEntropy(file, opt);
            case "magic" -> cmdMagic(file, opt);
            default -> {
                System.err.println("Unknown command: " + cmd);
                usage();
                System.exit(2);
            }
        }
    }

    static void usage() {
        System.out.println("""
            ByteArsenal — small forensic-like CLI in one file

            Usage:
              java ByteArsenal hash    <file> [sha256|sha1|md5 ...]
              java ByteArsenal hexdump <file> [--from=0x0|123] [--len=256] [--width=16]
              java ByteArsenal strings <file> [--min=6] [--max=200] [--utf16=1] [--ascii=1]
              java ByteArsenal entropy <file> [--window=4096] [--step=4096] [--top=20]
              java ByteArsenal magic   <file> [--deep=1] [--max=2000000]

            Notes:
              - magic: without --deep, checks header only.
              - entropy prints top highest-entropy windows (good to spot packed/encrypted zones).
            """);
    }

    static Map<String, String> parseOpts(String[] args, int start) {
        Map<String, String> m = new HashMap<>();
        for (int i = start; i < args.length; i++) {
            String a = args[i];
            if (a.startsWith("--")) {
                int eq = a.indexOf('=');
                if (eq >= 0) m.put(a.substring(2, eq).toLowerCase(Locale.ROOT), a.substring(eq + 1));
                else m.put(a.substring(2).toLowerCase(Locale.ROOT), "1");
            }
        }
        return m;
    }

    static long parseLongSmart(String s) {
        if (s == null) return 0;
        String t = s.trim().toLowerCase(Locale.ROOT);
        try {
            if (t.startsWith("0x")) return Long.parseUnsignedLong(t.substring(2), 16);
            if (t.endsWith("k")) return Long.parseLong(t.substring(0, t.length() - 1)) * 1024L;
            if (t.endsWith("m")) return Long.parseLong(t.substring(0, t.length() - 1)) * 1024L * 1024L;
            return Long.parseLong(t);
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("Bad number: " + s);
        }
    }

    static int parseIntSmart(String s, int def) {
        if (s == null) return def;
        long v = parseLongSmart(s);
        if (v > Integer.MAX_VALUE) throw new IllegalArgumentException("Too large: " + s);
        return (int) v;
    }

    static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) sb.append(Character.forDigit((x >>> 4) & 0xF, 16)).append(Character.forDigit(x & 0xF, 16));
        return sb.toString();
    }

    static void cmdHash(Path file, Map<String, String> opt, String[] args, int startIdx) throws Exception {
        List<String> algs = new ArrayList<>();
        for (int i = start
