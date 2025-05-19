package Security;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;

public class DiffieHellman {
    /**
     * Performs a Diffie–Hellman key exchange simulation.
     *
     * @param q     a prime modulus
     * @param alpha a primitive root modulo q
     * @param xa    private key of party A (0 < xa < q)
     * @param xb    private key of party B (0 < xb < q)
     * @return a List containing [YA, YB, KA, KB]:
     *         YA = alpha^xa mod q,
     *         YB = alpha^xb mod q,
     *         KA = YB^xa mod q,
     *         KB = YA^xb mod q.
     */
    public List<Integer> getKeys(int q, int alpha, int xa, int xb) {
        // Use BigInteger for safe modular exponentiation
        BigInteger bigQ     = BigInteger.valueOf(q);
        BigInteger bigAlpha = BigInteger.valueOf(alpha);
        BigInteger bigXa    = BigInteger.valueOf(xa);
        BigInteger bigXb    = BigInteger.valueOf(xb);

        // Compute public values
        BigInteger YA = bigAlpha.modPow(bigXa, bigQ);
        BigInteger YB = bigAlpha.modPow(bigXb, bigQ);

        // Compute shared secrets
        BigInteger KA = YB.modPow(bigXa, bigQ);
        BigInteger KB = YA.modPow(bigXb, bigQ);

        // Return as ints
        return Arrays.asList(
                KA.intValue(),
                KB.intValue()
        );
    }

}
