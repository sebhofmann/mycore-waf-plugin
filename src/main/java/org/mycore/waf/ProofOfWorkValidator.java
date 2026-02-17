package org.mycore.waf;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Validator for Proof of Work challenges.
 */
public class ProofOfWorkValidator {

  /**
   * Validates a Proof of Work solution.
   *
   * @param solution the nonce found by the client
   * @param challenge the challenge string
   * @param difficulty the required number of leading zero bits
   * @return true if the solution is valid, false otherwise
   */
  public boolean validate(String solution, String challenge, int difficulty) {
    try {
      // Verify that the solution is a valid number
      long nonce = Long.parseLong(solution);

      // Compute hash of challenge + nonce
      String input = challenge + nonce;
      MessageDigest digest = MessageDigest.getInstance("SHA-256");
      byte[] hash = digest.digest(input.getBytes(StandardCharsets.UTF_8));

      // Check if hash has the required number of leading zero bits
      int zeroBits = countLeadingZeroBits(hash);

      return zeroBits >= difficulty;

    } catch (NumberFormatException | NoSuchAlgorithmException e) {
      return false;
    }
  }

  private int countLeadingZeroBits(byte[] hash) {
    int zeroBits = 0;
    for (byte b : hash) {
      if (b == 0) {
        zeroBits += 8;
      } else {
        // Count leading zeros in this byte
        zeroBits += Integer.numberOfLeadingZeros(b & 0xFF) - 24;
        break;
      }
    }
    return zeroBits;
  }
}
