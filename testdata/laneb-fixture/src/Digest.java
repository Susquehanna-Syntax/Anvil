// Planted for Lane B's fixture. Never compiled.
import java.security.MessageDigest;

public class Digest {
    byte[] hash(byte[] in) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        return md.digest(in);
    }
}
