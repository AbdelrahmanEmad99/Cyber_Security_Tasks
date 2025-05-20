package Security;

import java.util.Arrays;
import java.util.List;

public class ElGamal {

    // Modular exponentiation: (base^exp) % mod
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

    private long modInverse(long a, long m) {
        long m0 = m, t, q;
        long x0 = 0, x1 = 1;

        if (m == 1)
            return 0;

        while (a > 1) {
            q = a / m;
            t = m;
            m = a % m;
            a = t;

            t = x0;
            x0 = x1 - q * x0;
            x1 = t;
        }

        if (x1 < 0)
            x1 += m0;

        return x1;
    }

    /**
     * Encrypts a message m under ElGamal.
     *
     * @param q     a prime modulus
     * @param alpha a generator (primitive root mod q)
     * @param y     recipient’s public key (y = alpha^x mod q)
     * @param k     ephemeral secret (0 < k < q), must be random and co-prime to q−1
     * @param m     the plaintext message (0 ≤ m < q)
     * @return      a List<Long> [c1, c2] where
     *                c1 = alpha^k mod q
     *                c2 = (m * y^k) mod q
     */
    public List<Long> encrypt(int q, int alpha, int y, int k, int m) {
        long c1 = modPow(alpha, k, q);
        long s = modPow(y, k, q); // y^k mod q
        long c2 = (s * m) % q;
        return Arrays.asList(c1, c2);
    }

    /**
     * Decrypts an ElGamal ciphertext pair (c1, c2).
     *
     * @param c1   first part of ciphertext (alpha^k mod q)
     * @param c2   second part of ciphertext ((m * y^k) mod q)
     * @param x    recipient’s private key (such that y = alpha^x mod q)
     * @param q    the same prime modulus
     * @return     the recovered plaintext message m
     */
    public int decrypt(int c1, int c2, int x, int q) {
        long s = modPow(c1, x, q);           // s = c1^x mod q
        long sInv = modInverse(s, q);        // s^-1 mod q
        long m = (c2 * sInv) % q;
        return (int) m;
    }
}
