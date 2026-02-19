import java.io.InputStream;
import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.*;

import static java.nio.file.StandardWatchEventKinds.*;

public class FsWatch {

    public static void main(String[] args) throws Exception {
        if (args.length < 1 || has(args, "--help")) {
            usage();
            return;
        }

        Path root = Paths.get(args[0]).toAbsolutePath().normalize();
        if (!Files.exists(root)) {
            System.err.println("Path not found: " + root);
            System.exit(2);
        }

        Map<String, String> opt = parseOpts(args, 1);

        boolean recursive = boolOpt(opt, "recursive", true);
        boolean hash = boolOpt(opt, "hash", false);
        boolean onlyFiles = boolOpt(opt, "onlyfiles", false);
        long maxHashBytes = longOpt(opt, "maxhash", 50L * 1024 * 1024); // 50MB default
        String filter = opt.getOrDefault("filter", "");
        java.util.regex.Pattern pattern = filter.isBlank() ? null : java.util.regex.Pattern.compile(filter);

        WatchService ws = FileSystems.getDefault().newWatchService();
        Map<WatchKey, Path> keyToDir = new HashMap<>();

        if (Files.isDirectory(root)) {
            if (recursive) registerTree(ws, root, keyToDir);
            else registerDir(ws, root, keyToDir);
        } else {
            Path parent = root.getParent();
            if (parent == null) parent = Paths.get(".").toAbsolutePath().normalize();
            registerDir(ws, parent, keyToDir);
        }

        System.out.println("== FsWatch ==");
        System.out.println("Root:       " + root);
        System.out.println("Recursive:  " + recursive);
        System.out.println("Only files: " + onlyFiles);
        System.out.println("Filter:     " + (pattern == null ? "(none)" : pattern.pattern()));
        System.out.println("Hash:       " + (hash ? ("SHA-256 (max " + maxHashBytes + " bytes)") : "off"));
        System.out.println();

        while (true) {
            WatchKey key = ws.take();
            Path dir = keyToDir.get(key);
            if (dir == null) {
                key.reset();
                continue;
            }

            for (WatchEvent<?> ev : key.pollEvents()) {
                WatchEvent.Kind<?> kind = ev.kind();

                if (kind == OVERFLOW) {
                    System.out.println(ts() + " OVERFLOW " + dir);
                    continue;
                }

                Path name = (Path) ev.context();
                Path full = dir.resolve(name).normalize();

                if (pattern != null && !pattern.matcher(full.toString()).find()) continue;
                if (onlyFiles && Files.isDirectory(full)) continue;

                // If user passed a specific file path as root, filter out other siblings
                if (Files.isRegularFile(root) && !full.equals(root)) continue;

                String out = ts() + " " + kind.name() + " " + full;

                if (hash && (kind == ENTRY_CREATE || kind == ENTRY_MODIFY)) {
                    try {
                        if (Files.isRegularFile(full)) {
                            long size = Files.size(full);
                            if (size <= maxHashBytes) {
                                out += " sha256=" + sha256Hex(full);
                            } else {
                                out += " sha256=(skipped size=" + size + ")";
                            }
                        }
                    } catch (Exception e) {
                        out += " sha256=(error " + e.getClass().getSimpleName() + ")";
                    }
                }

                System.out.println(out);

                // If a new directory appears and we're recursive, start watching it too
                if (recursive && kind == ENTRY_CREATE) {
                    try {
                        if (Files.isDirectory(full)) {
                            registerTree(ws, full, keyToDir);
                            System.out.println(ts() + " WATCHING_NEW_DIR " + full);
                        }
                    } catch (Exception ignored) {}
                }
            }

            boolean valid = key.reset();
            if (!valid) {
                keyToDir.remove(key);
                if (keyToDir.isEmpty()) break;
            }
        }
    }

    static void usage() {
        System.out.println("""
                FsWatch — directory watcher (single-file, Java standard library)

                Usage:
                  java FsWatch <path> [--recursive=1|0] [--filter=REGEX] [--hash=1|0]
                                   [--onlyfiles=1|0] [--maxhash=BYTES]

                Examples:
                  java FsWatch .
                  java FsWatch . --filter=\\.java$
                  java FsWatch src --recursive=1 --hash=1
                  java FsWatch README.md

                Notes:
                  - --filter matches against the full resolved path string.
                  - --hash computes SHA-256 for CREATE/MODIFY (skips large files by --maxhash).
                """);
    }

    static String ts() {
        return Instant.now().toString();
    }

    static void registerDir(WatchService ws, Path dir, Map<WatchKey, Path> keyToDir) throws Exception {
        WatchKey k = dir.register(ws, ENTRY_CREATE, ENTRY_DELETE, ENTRY_MODIFY);
        keyToDir.put(k, dir);
    }

    static void registerTree(WatchService ws, Path root, Map<WatchKey, Path> keyToDir) throws Exception {
        Files.walkFileTree(root, new SimpleFileVisitor<>() {
            @Override public FileVisitResult preVisitDirectory(Path dir, BasicFileAttributes attrs) throws java.io.IOException {
                try {
                    registerDir(ws, dir, keyToDir);
                } catch (Exception e) {
                    throw new java.io.IOException(e);
                }
                return FileVisitResult.CONTINUE;
            }
        });
    }

    static String sha256Hex(Path p) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        try (InputStream in = Files.newInputStream(p)) {
            byte[] buf = new byte[8192];
            int n;
            while ((n = in.read(buf)) >= 0) md.update(buf, 0, n);
        }
        byte[] dig = md.digest();
        StringBuilder sb = new StringBuilder(dig.length * 2);
        for (byte b : dig) sb.append(Character.forDigit((b >>> 4) & 0xF, 16))
                             .append(Character.forDigit(b & 0xF, 16));
        return sb.toString().toUpperCase(Locale.ROOT);
    }

    static boolean has(String[] args, String flag) {
        for (String a : args) if (a.equalsIgnoreCase(flag)) return true;
        return false;
    }

    static Map<String, String> parseOpts(String[] args, int start) {
        Map<String, String> m = new LinkedHashMap<>();
        for (int i = start; i < args.length; i++) {
            String a = args[i];
            if (!a.startsWith("--")) continue;
            int eq = a.indexOf('=');
            if (eq >= 0) m.put(a.substring(2, eq).toLowerCase(Locale.ROOT), a.substring(eq + 1));
            else m.put(a.substring(2).toLowerCase(Locale.ROOT), "1");
        }
        return m;
    }

    static boolean boolOpt(Map<String, String> opt, String k, boolean def) {
        String v = opt.get(k);
        if (v == null) return def;
        return !(v.equals("0") || v.equalsIgnoreCase("false") || v.equalsIgnoreCase("no"));
    }

    static long longOpt(Map<String, String> opt, String k, long def) {
        String v = opt.get(k);
        if (v == null) return def;
        try { return Long.parseLong(v.trim()); } catch (Exception e) { return def; }
    }
}
