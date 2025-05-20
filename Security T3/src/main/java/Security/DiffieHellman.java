package Security;

import java.util.Arrays;
import java.util.List;

public class DiffieHellman {

    // Manual modular exponentiation: base^exp % mod using long
    private long modPow(long base, long exp, long mod) {
        long result = 1;
        base %= mod;
        while (exp > 0) {
            if ((exp & 1) == 1)
                result = (result * base) % mod;

            base = (base * base) % mod;
            exp >>= 1;
        }
        return result;
    }

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
        long YA = modPow(alpha, xa, q);
        long YB = modPow(alpha, xb, q);
        long KA = modPow(YB, xa, q);
        long KB = modPow(YA, xb, q);
        return Arrays.asList((int)KA, (int)KB);
    }
}
