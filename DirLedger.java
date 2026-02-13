import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.MessageDigest;
import java.util.*;
import java.util.concurrent.*;

public class DirLedger {

    static final int VERSION = 1;
    static final int MAGIC = 0x444C4D31; // "DLM1"
    static final String ALG = "SHA-256";

    public static void main(String[] args) throws Exception {
        if (args.length < 2) {
            usage();
            return;
        }

        String cmd = args[0].toLowerCase(Locale.ROOT);
        Path root = Paths.get(args[1]).toAbsolutePath().normalize();

        Map<String, String> opt = parseOpts(args, 2);

        switch (cmd) {
            case "build" -> build(root, opt);
            case "verify" -> verify(root, opt);
            case "peek" -> peek(opt);
            default -> {
                System.err.println("Unknown command: " + cmd);
                usage();
                System.exit(2);
            }
        }
    }

    static void usage() {
        System.out.println("""
            DirLedger — directory manifest + verifier (single-file)

            Build:
              java DirLedger build  <dir> --out=ledger.dlm [--hash=1] [--maxhash=1m] [--threads=8] [--follow=0]

            Verify:
              java DirLedger verify <dir> --in=ledger.dlm [--rehash=1] [--threads=8] [--follow=0]

            Peek (no dir needed):
              java DirLedger peek --in=ledger.dlm

            Notes:
              - --hash=1 hashes files up to --maxhash (default 1m)
              - verify compares existence + size, and (if present) hash; mtime is informational
            """);
    }

    static Map<String, String> parseOpts(String[] args, int start) {
        Map<String, String> m = new HashMap<>();
        for (int i = start; i < args.length; i++) {
            String a = args[i];
            if (!a.startsWith("--")) continue;
            int eq = a.indexOf('=');
            if (eq >= 0) m.put(a.substring(2, eq).toLowerCase(Locale.ROOT), a.substring(eq + 1));
            else m.put(a.substring(2).toLowerCase(Locale.ROOT), "1");
        }
        return m;
    }

    static boolean on(Map<String, String> opt, String key, boolean def) {
        String v = opt.get(key);
        if (v == null) return def;
        return !v.equals("0") && !v.equalsIgnoreCase("false");
    }

    static int iopt(Map<String, String> opt, String key, int def) {
        String v = opt.get(key);
        if (v == null) return def;
        long n = parseLongSmart(v);
        if (n > Integer.MAX_VALUE) throw new IllegalArgumentException("Too large: " + key);
        return (int) n;
    }

    static long lopt(Map<String, String> opt, String key, long def) {
        String v = opt.get(key);
        if (v == null) return def;
        return parseLongSmart(v);
    }

    static long parseLongSmart(String s) {
        String t = s.trim().toLowerCase(Locale.ROOT);
        if (t.startsWith("0x")) return Long.parseUnsignedLong(t.substring(2), 16);
        long mul = 1;
        if (t.endsWith("k")) { mul = 1024L; t = t.substring(0, t.length() - 1); }
        else if (t.endsWith("m")) { mul = 1024L * 1024L; t = t.substring(0, t.length() - 1); }
        else if (t.endsWith("g")) { mul = 1024L * 1024L * 1024L; t = t.substring(0, t.length() - 1); }
        return Long.parseLong(t) * mul;
    }

    static class Rec {
        final String rel;
        final long size;
        final long mtime;
        final boolean hashed;
        volatile byte[] hash; // 32 bytes if hashed

        Rec(String rel, long size, long mtime, boolean hashed) {
            this.rel = rel;
            this.size = size;
            this.mtime = mtime;
            this.hashed = hashed;
        }
    }

    static void build(Path root, Map<String, String> opt) throws Exception {
        if (!Files.isDirectory(root)) {
            System.err.println("Not a directory: " + root);
            System.exit(2);
        }

        Path out = Paths.get(opt.getOrDefault("out", "ledger.dlm")).toAbsolutePath().normalize();
        boolean doHash = on(opt, "hash", false);
        long maxHash = lopt(opt, "maxhash", 1024L * 1024L);
        int threads = Math.max(1, iopt(opt, "threads", Math.max(2, Runtime.getRuntime().availableProcessors())));
        boolean follow = on(opt, "follow", false);

        List<Rec> list = new ArrayList<>(8192);
        long[] totals = new long[2]; // [files, bytes]

        EnumSet<FileVisitOption> visitOpt = follow ? EnumSet.of(FileVisitOption.FOLLOW_LINKS) : EnumSet.noneOf(FileVisitOption.class);

        Files.walkFileTree(root, visitOpt, Integer.MAX_VALUE, new SimpleFileVisitor<>() {
            @Override
            public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) {
                if (!attrs.isRegularFile()) return FileVisitResult.CONTINUE;
                Path rel = root.relativize(file);
                String relStr = rel.toString().replace('\\', '/');
                long size = attrs.size();
                long mtime = attrs.lastModifiedTime().toMillis();
                boolean hashed = doHash && size <= maxHash;
                list.add(new Rec(relStr, size, mtime, hashed));
                totals[0]++;
                totals[1] += size;
                return FileVisitResult.CONTINUE;
            }
        });

        System.out.println("Root:    " + root);
        System.out.println("Out:     " + out);
        System.out.println("Files:   " + totals[0]);
        System.out.println("Bytes:   " + totals[1]);
        System.out.println("Hashing: " + (doHash ? ("on (<= " + maxHash + " bytes, " + threads + " threads)") : "off"));

        if (doHash) {
            hashAll(root, list, threads);
        }

        writeLedger(out, root, list);

        System.out.println("Done. Wrote " + out + " (" + list.size() + " records)");
    }

    static void verify(Path root, Map<String, String> opt) throws Exception {
        if (!Files.isDirectory(root)) {
            System.err.println("Not a directory: " + root);
            System.exit(2);
        }

        Path in = Paths.get(opt.getOrDefault("in", "ledger.dlm")).toAbsolutePath().normalize();
        boolean rehash = on(opt, "rehash", true);
        int threads = Math.max(1, iopt(opt, "threads", Math.max(2, Runt
