// Planted for the candidates-per-scan control: DES. Never compiled. Since 2026-10-03 the Java plant
// trips GitLab's java_crypto_rule-CipherDESInsecure, one of the Java rules left after the
// LGPL-3.0-derived ones (find-sec-bugs) were excluded; the command-injection rule it used to trip
// is one of those.
import javax.crypto.Cipher;

public class BadCipher {
    Cipher cipher() throws Exception {
        return Cipher.getInstance("DES/CBC/PKCS5Padding");
    }
}
