package net.typeblog.socks.util;

public final class PortTest {
    public static void main(String[] args) {
        for (String invalid : new String[]{null, "", "0", "65536", "-1", "+53", "abc", " 53", "99999999999999999999"}) {
            if (Utility.parsePort(invalid) != -1) throw new AssertionError("Accepted invalid port: " + invalid);
        }
        for (String valid : new String[]{"1", "53", "1080", "65535", "00053"}) {
            if (Utility.parsePort(valid) != Integer.parseInt(valid)) throw new AssertionError("Rejected valid port: " + valid);
        }
        java.lang.System.out.println("PASS: port boundaries and malformed input");
    }
}
