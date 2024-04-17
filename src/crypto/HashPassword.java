package crypto;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class HashPassword {
  public static String hash(String password, byte[] salt) {
    String generatedHash = null;
    try {
      MessageDigest md = MessageDigest.getInstance("SHA-512");
      md.update(salt);
      byte[] bytes = md.digest(password.getBytes());
      generatedHash = byte2hex(bytes);
    } catch (NoSuchAlgorithmException e) {
      e.printStackTrace();
    }
    return generatedHash;
  }

  public static String byte2hex(byte[] bytes) {
    StringBuilder strHex = new StringBuilder();
    for (byte b : bytes) {
      strHex.append(String.format("%02x", b));
    }
    return strHex.toString();
  }
}
