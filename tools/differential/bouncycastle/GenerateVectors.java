import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.crypto.fpe.FPEEngine;
import org.bouncycastle.crypto.fpe.FPEFF1Engine;
import org.bouncycastle.crypto.params.FPEParameters;
import org.bouncycastle.crypto.params.KeyParameter;

/**
 * Generates FF1 differential test vectors with Bouncy Castle's FPEFF1Engine
 * and prints them as JSON for ff1/testdata/differential_bouncycastle.json.
 *
 * <p>Radix 65536 is deliberately excluded: Bouncy Castle's
 * SP80038G.calculateP_FF1 hardcodes P[3] = 0, so it encodes radix 65536 as
 * 00 00 00 instead of 01 00 00 and produces wrong ciphertexts there. The
 * generator records its output for one such input as evidence, but no
 * radix-65536 vector is emitted. The Rust fpe crate covers radix 65536.
 *
 * <p>Inputs are fixed edge cases followed by SplitMix64 pseudorandom
 * parameters from a fixed seed, so the output is reproducible. Run it
 * through ../generate.sh.
 */
public final class GenerateVectors {
    private static final long SEED = 0x4243_4646_3147_454EL; // "BCFF1GEN"
    private static final int RANDOM_CASES = 500;
    private static final int MAX_RADIX = 65535; // see class comment

    private static final int[] EDGE_RADIXES = {
        2, 3, 10, 16, 36, 62, 64, 255, 256, 257, 999, 1000, 1023, 1024, 1025, 32767, 32768, 32769, 65535,
    };

    private static long state = SEED;

    private static long next() {
        state += 0x9E3779B97F4A7C15L;
        long z = state;
        z = (z ^ (z >>> 30)) * 0xBF58476D1CE4E5B9L;
        z = (z ^ (z >>> 27)) * 0x94D049BB133111EBL;
        return z ^ (z >>> 31);
    }

    private static int below(int n) {
        return (int) Long.remainderUnsigned(next(), n);
    }

    private static byte[] bytes(int n) {
        byte[] b = new byte[n];
        for (int i = 0; i < n; i++) {
            b[i] = (byte) next();
        }
        return b;
    }

    private static int[] numerals(int n, int radix) {
        int[] x = new int[n];
        for (int i = 0; i < n; i++) {
            x[i] = below(radix);
        }
        return x;
    }

    private static int minLen(int radix) {
        int n = 0;
        for (long d = 1; d < 1_000_000; d *= radix) {
            n++;
        }
        return Math.max(n, 2);
    }

    private record Case(String note, byte[] key, int radix, byte[] tweak, int[] pt) {}

    private static final List<Case> cases = new ArrayList<>();

    private static void add(String note, int radix, int[] pt, int tweakLen) {
        byte[] key = bytes(new int[] {16, 24, 32}[cases.size() % 3]);
        cases.add(new Case(note, key, radix, bytes(tweakLen), pt));
    }

    private static void addRandom(String note, int radix, int n, int tweakLen) {
        add(note, radix, numerals(n, radix), tweakLen);
    }

    /** Runs FPEFF1Engine; radix > 256 uses 16-bit big-endian numerals. */
    private static int[] crypt(boolean encrypt, byte[] key, int radix, byte[] tweak, int[] x) {
        FPEEngine engine = new FPEFF1Engine();
        engine.init(encrypt, new FPEParameters(new KeyParameter(key), radix, tweak));
        boolean wide = radix > 256;
        byte[] in = new byte[wide ? 2 * x.length : x.length];
        for (int i = 0; i < x.length; i++) {
            if (wide) {
                in[2 * i] = (byte) (x[i] >>> 8);
                in[2 * i + 1] = (byte) x[i];
            } else {
                in[i] = (byte) x[i];
            }
        }
        byte[] out = new byte[in.length];
        engine.processBlock(in, 0, in.length, out, 0);
        int[] y = new int[x.length];
        for (int i = 0; i < y.length; i++) {
            y[i] = wide ? ((out[2 * i] & 0xff) << 8) | (out[2 * i + 1] & 0xff) : out[i] & 0xff;
        }
        return y;
    }

    private static int[] encrypt(Case c) {
        if (c.radix > MAX_RADIX) {
            throw new IllegalStateException("radix " + c.radix + " is not supported correctly by Bouncy Castle");
        }
        int[] ct = crypt(true, c.key, c.radix, c.tweak, c.pt);
        if (!java.util.Arrays.equals(crypt(false, c.key, c.radix, c.tweak, ct), c.pt)) {
            throw new IllegalStateException("decrypt(encrypt(pt)) != pt");
        }
        return ct;
    }

    private static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder();
        for (byte x : b) {
            sb.append(String.format("%02x", x & 0xff));
        }
        return sb.toString();
    }

    private static String list(int[] x) {
        StringBuilder sb = new StringBuilder("[");
        for (int i = 0; i < x.length; i++) {
            sb.append(i == 0 ? "" : ", ").append(x[i]);
        }
        return sb.append(']').toString();
    }

    public static void main(String[] args) {
        String version = args.length > 0 ? args[0] : "unknown";

        // Oracle self-check: NIST FF1 sample 1.
        int[] s1 = crypt(true, org.bouncycastle.util.encoders.Hex.decode("2B7E151628AED2A6ABF7158809CF4F3C"), 10,
                new byte[0], new int[] {0, 1, 2, 3, 4, 5, 6, 7, 8, 9});
        if (!java.util.Arrays.equals(s1, new int[] {2, 4, 3, 3, 4, 7, 7, 4, 8, 4})) {
            throw new IllegalStateException("NIST sample 1 failed: " + list(s1));
        }
        // Evidence for the radix-65536 exclusion (the correct output is
        // [18476, 48157]).
        int[] bug = crypt(true, new byte[16], 65536, new byte[8], new int[] {0, 1});

        for (int radix : EDGE_RADIXES) {
            int lo = minLen(radix);
            int[] zeros = new int[lo];
            int[] maxes = new int[lo];
            java.util.Arrays.fill(maxes, radix - 1);
            add("edge radix, minimum length, all zero", radix, zeros, 0);
            add("edge radix, minimum length, all radix-1", radix, maxes, 8);
            addRandom("edge radix, minimum length + 1", radix, lo + 1, 13);
            int n = lo + 2 + below(40);
            addRandom("edge radix, random length", radix, n, below(40));
        }
        for (int n : new int[] {2, 3, 12, 13, 29, 30, 64}) {
            addRandom("radix 65535 length boundary", 65535, n, 8);
        }
        add("radix 65535 digits 32767/32768/65534", 65535, new int[] {32767, 32768, 65534}, 8);
        for (int n : new int[] {463, 464}) {
            addRandom("radix 2, v = 232 (b = 29)", 2, n, 0);
            addRandom("radix 2, v = 232 (b = 29)", 2, n, 17);
        }
        addRandom("radix 10, d = 20", 10, 58, 3);
        addRandom("radix 256, n = 57", 256, 57, 8);
        for (int t = 0; t <= 40; t++) {
            addRandom("tweak length sweep", 36, 19, t);
        }
        for (int t : new int[] {255, 256, 1000}) {
            addRandom("tweak length sweep", 36, 19, t);
        }
        for (int i = 0; i < RANDOM_CASES; i++) {
            int radix;
            switch (below(4)) {
                case 0 -> radix = EDGE_RADIXES[below(EDGE_RADIXES.length)];
                case 1 -> radix = 1 << (1 + below(15)); // 2 .. 32768
                default -> radix = 2 + below(MAX_RADIX - 1); // 2 .. 65535
            }
            int lo = minLen(radix);
            int r = below(20);
            int n = r == 0 ? lo + below(600) : r <= 3 ? lo + below(200) : lo + below(40);
            r = below(20);
            int t = r == 0 ? below(600) : r <= 5 ? below(128) : below(33);
            r = below(20);
            int[] pt;
            if (r == 0) {
                pt = new int[n];
            } else if (r == 1) {
                pt = new int[n];
                java.util.Arrays.fill(pt, radix - 1);
            } else {
                pt = numerals(n, radix);
            }
            add("random", radix, pt, t);
        }

        StringBuilder out = new StringBuilder();
        out.append("{\n");
        out.append(" \"description\": \"FF1 vectors computed by Bouncy Castle (FPEFF1Engine) for differential testing: fixed edge cases, then SplitMix64 pseudorandom parameters over radix 2..65535, all AES key sizes, and tweaks of 0..1000 bytes. Radix 65536 is excluded because Bouncy Castle encodes it incorrectly in P (see radix65536_excluded). Every input satisfies radix^n >= 1000000. Regenerate with tools/differential/generate.sh.\",\n");
        out.append(" \"generator\": \"tools/differential/bouncycastle\",\n");
        out.append(" \"library\": \"Bouncy Castle (org.bouncycastle:bcprov-jdk18on)\",\n");
        out.append(" \"library_version\": \"").append(version).append("\",\n");
        out.append(" \"seed\": \"").append(String.format("0x%016x", SEED)).append("\",\n");
        out.append(" \"pinned\": {\"bcprov-jdk18on\": \"").append(version)
                .append("\", \"java\": \"").append(System.getProperty("java.vendor")).append(' ')
                .append(System.getProperty("java.runtime.version")).append("\"},\n");
        out.append(" \"max_radix\": ").append(MAX_RADIX).append(",\n");
        out.append(" \"radix65536_excluded\": {\"reason\": \"SP80038G.calculateP_FF1 hardcodes P[3] = 0, encoding radix 65536 as 00 00 00\", ")
                .append("\"key\": \"").append(hex(new byte[16])).append("\", \"tweak\": \"").append(hex(new byte[8]))
                .append("\", \"pt\": [0, 1], \"bouncycastle_ct\": ").append(list(bug)).append("},\n");
        out.append(" \"vectors\": [\n");
        for (int i = 0; i < cases.size(); i++) {
            Case c = cases.get(i);
            int[] ct = encrypt(c);
            out.append("  {\"id\": ").append(i).append(", \"note\": \"").append(c.note)
                    .append("\", \"key\": \"").append(hex(c.key)).append("\", \"radix\": ").append(c.radix)
                    .append(", \"tweak\": \"").append(hex(c.tweak)).append("\",\n   \"pt\": ").append(list(c.pt))
                    .append(",\n   \"ct\": ").append(list(ct)).append('}')
                    .append(i + 1 < cases.size() ? ",\n" : "\n");
        }
        out.append(" ]\n}\n");
        System.out.print(out);
        System.err.println(cases.size() + " vectors; Bouncy Castle radix-65536 output for [0, 1]: " + list(bug));
    }
}
