import java.security.MessageDigest;

public class Hashes {
    byte[] md5(byte[] in) throws Exception {
        // ruleid: java.weak-hash
        return MessageDigest.getInstance("MD5").digest(in);
    }

    byte[] sha1(byte[] in) throws Exception {
        // ruleid: java.weak-hash
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        return md.digest(in);
    }

    byte[] sha256(byte[] in) throws Exception {
        // ok: java.weak-hash
        return MessageDigest.getInstance("SHA-256").digest(in);
    }
}
