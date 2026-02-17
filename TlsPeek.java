import javax.net.ssl.*;
import java.io.ByteArrayInputStream;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.text.SimpleDateFormat;
import java.util.*;

public class TlsPeek {

    public static void main(String[] args) throws Exception {
        if (args.length < 1 || has(args, "--help")) {
            usage();
            return;
        }

        Target t = parseTarget(args[0]);
        Map<String, String> opt = parseOpts(args, 1);

        int timeoutMs = intOpt(opt, "timeout", 3500);
        boolean verifyHost = boolOpt(opt, "verify", true);
        boolean insecure = boolOpt(opt, "insecure", false);

        String sni = opt.getOrDefault("sni", t.host);
        String alpn = opt.getOrDefault("alpn", "h2,http/1.1");
        String protocols = opt.getOrDefault("protocols", "TLSv1.3,TLSv1.2");
        String ciphers = opt.getOrDefault("ciphers", "");

        SSLContext ctx = insecure ? insecureContext() : defaultContext();
        SSLSocketFactory sf = ctx.getSocketFactory();

        try (Socket raw = new Socket()) {
            raw.connect(new InetSocketAddress(t.host, t.port), timeoutMs);
            raw.setSoTimeout(timeoutMs);

            try (SSLSocket s = (SSLSocket) sf.createSocket(raw, t.host, t.port, true)) {
                SSLParameters p = s.getSSLParameters();

                // SNI
                if (sni != null && !sni.isBlank()) {
                    try {
                        p.setServerNames(List.of(new SNIHostName(sni)));
                    } catch (IllegalArgumentException ignored) {
                        // SNIHostName falha com certos inputs (ex: IP malformado). Só ignora.
                    }
                }

                // Hostname verification (HTTPS-style)
                if (verifyHost) {
                    p.setEndpointIdentificationAlgorithm("HTTPS");
                }

                // ALPN
                String[] alpnList = splitCsv(alpn);
                if (alpnList.length > 0) {
                    try { p.setApplicationProtocols(alpnList); } catch (Throwable ignored) {}
                }

                // Protocols
                String[] protos = splitCsv(protocols);
                if (protos.length > 0) s.setEnabledProtocols(protos);

                // Ciphers (opcional)
                if (!ciphers.isBlank()) {
                    String[] cs = splitCsv(ciphers);
                    if (cs.length > 0) s.setEnabledCipherSuites(cs);
                }

                s.setSSLParameters(p);

                long t0 = System.nanoTime();
                s.startHandshake();
                long dtMs = (System.nanoTime() - t0) / 1_000_000L;

                SSLSession sess = s.getSession();

                System.out.println("== TlsPeek ==");
                System.out.println("Remote: " + t.host + ":" + t.port);
                System.out.println("SNI:    " + (sni == null ? "(none)" : sni));
                System.out.println("Verify: " + (verifyHost ? "on" : "off") + (insecure ? " (trust-all)" : ""));
                System.out.println("Handshake: " + dtMs + " ms");
                System.out.println();

                System.out.println("Negotiated:");
                System.out.println("  Protocol: " + sess.getProtocol());
                System.out.println("  Cipher:   " + sess.getCipherSuite());

                String appProto = "";
                try { appProto = s.getApplicationProtocol(); } catch (Throwable ignored) {}
                if (appProto != null && !appProto.isBlank()) {
                    System.out.println("  ALPN:     " + appProto);
                }

                System.out.println();
                System.out.println("Peer certificates:");

                Certificate[] chain = sess.getPeerCertificates();
                for (int i = 0; i < chain.length; i++) {
                    X509Certificate cert = toX509(chain[i]);
                    System.out.println();
                    System.out.println("  [" + i + "] " + cert.getSubjectX500Principal().getName());
                    System.out.println("      Issuer:  " + cert.getIssuerX500Principal().getName());
                    System.out.println("      Serial:  0x" + cert.getSerialNumber().toString(16));
                    System.out.println("      Valid:   " + fmt(cert.getNotBefore()) + "  ->  " + fmt(cert.getNotAfter()));
                    System.out.println("      SigAlg:  " + cert.getSigAlgName());

                    PublicKey pk = cert.getPublicKey();
                    System.out.println("      PubKey:  " + pubKeyInfo(pk));

                    List<String> sans = subjectAltNames(cert);
                    if (!sans.isEmpty()) {
                        System.out.println("      SANs:");
                        for (String san : sans) System.out.println("        - " + san);
                    }

                    System.out.println("      SHA-256: " + fp(cert.getEncoded(), "SHA-256"));
                    System.out.println("      SHA-1:   " + fp(cert.getEncoded(), "SHA-1"));
                }
            }
        }
    }

    static void usage() {
        System.out.println("""
                TlsPeek — TLS handshake + certificate chain inspector (single-file)

                Usage:
                  java TlsPeek <host[:port]> [--sni=example.com] [--timeout=3500]
                               [--alpn=h2,http/1.1] [--protocols=TLSv1.3,TLSv1.2]
                               [--verify=1|0] [--insecure=1|0] [--ciphers=...]

                Examples:
                  java TlsPeek example.com
                  java TlsPeek example.com:443 --alpn=h2,http/1.1
                  java TlsPeek 1.1.1.1:443 --sni=cloudflare-dns.com
                  java TlsPeek localhost:8443 --verify=0 --insecure=1

                Notes:
                  - --verify=1 enables HTTPS hostname verification.
                  - --insecure=1 trusts all certs (useful for self-signed / labs).
                """);
    }

    // ---- parsing ----

    static class Target {
        final String host;
        final int port;
        Target(String host, int port) { this.host = host; this.port = port; }
    }

    static Target parseTarget(String s) {
        String x = s.trim();

        // allow https://host:port
        if (x.startsWith("https://")) x = x.substring("https://".length());
        if (x.startsWith("tls://"))   x = x.substring("tls://".length());

        int port = 443;
        String host = x;

        int idx = x.lastIndexOf(':');
        if (idx > 0 && idx < x.length() - 1 && x.indexOf(']') < 0) { // crude (avoid IPv6 bracket edge)
            host = x.substring(0, idx);
            try { port = Integer.parseInt(x.substring(idx + 1)); } catch (Exception ignored) {}
        }

        host = host.replaceAll("^\\[|\\]$", ""); // strip [ ] if user passed IPv6
        return new Target(host, port);
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

    static boolean has(String[] args, String flag) {
        for (String a : args) if (a.equalsIgnoreCase(flag)) return true;
        return false;
    }

    static boolean boolOpt(Map<String, String> opt, String k, boolean def) {
        String v = opt.get(k);
        if (v == null) return def;
        return !(v.equals("0") || v.equalsIgnoreCase("false") || v.equalsIgnoreCase("no"));
    }

    static int intOpt(Map<String, String> opt, String k, int def) {
        String v = opt.get(k);
        if (v == null) return def;
        try { return Integer.parseInt(v.trim()); } catch (Exception e) { return def; }
    }

    static String[] splitCsv(String s) {
        if (s == null) return new String[0];
        String[] parts = s.split(",");
        List<String> out = new ArrayList<>();
        for (String p : parts) {
            String t = p.trim();
            if (!t.isEmpty()) out.add(t);
        }
        return out.toArray(new String[0]);
    }

    // ---- TLS contexts ----

    static SSLContext defaultContext() throws Exception {
        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(null, null, null);
        return ctx;
    }

    static SSLContext insecureContext() throws Exception {
        TrustManager tm = new X509TrustManager() {
            public void checkClientTrusted(X509Certificate[] chain, String authType) {}
            public void checkServerTrusted(X509Certificate[] chain, String authType) {}
            public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
        };
        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(null, new TrustManager[]{tm}, null);
        return ctx;
    }

    // ---- cert helpers ----

    static X509Certificate toX509(Certificate c) throws Exception {
        if (c instanceof X509Certificate x) return x;
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(c.getEncoded()));
    }

    static String fmt(Date d) {
        return new SimpleDateFormat("yyyy-MM-dd HH:mm:ss Z").format(d);
    }

    static List<String> subjectAltNames(X509Certificate cert) {
        try {
            Collection<List<?>> sans = cert.getSubjectAlternativeNames();
            if (sans == null) return List.of();
            List<String> out = new ArrayList<>();
            for (List<?> e : sans) {
                if (e.size() < 2) continue;
                Integer type = (Integer) e.get(0);
                Object val = e.get(1);
                out.add(sanType(type) + ": " + String.valueOf(val));
            }
            return out;
        } catch (Exception ignored) {
            return List.of();
        }
    }

    static String sanType(Integer t) {
        if (t == null) return "SAN";
        return switch (t) {
            case 1 -> "rfc822Name";
            case 2 -> "dNSName";
            case 6 -> "uRID";
            case 7 -> "iPAddress";
            case 8 -> "registeredID";
            default -> "type#" + t;
        };
    }

    static String fp(byte[] data, String alg) throws Exception {
        MessageDigest md = MessageDigest.getInstance(alg);
        byte[] dig = md.digest(data);
        StringBuilder sb = new StringBuilder(dig.length * 3);
        for (int i = 0; i < dig.length; i++) {
            int b = dig[i] & 0xFF;
            sb.append(hex2(b));
            if (i + 1 < dig.length) sb.append(':');
        }
        return sb.toString();
    }

    static String hex2(int b) {
        char hi = Character.forDigit((b >>> 4) & 0xF, 16);
        char lo = Character.forDigit(b & 0xF, 16);
        return ("" + Character.toUpperCase(hi) + Character.toUpperCase(lo));
    }

    static String pubKeyInfo(PublicKey pk) {
        String alg = pk.getAlgorithm();
        int bits = -1;

        try {
            if (pk instanceof RSAPublicKey r) bits = r.getModulus().bitLength();
            else if (pk instanceof ECPublicKey e) bits = e.getParams().getCurve().getField().getFieldSize();
        } catch (Exception ignored) {}

        if (bits > 0) return alg + " (" + bits + " bits)";
        return alg;
    }
}
