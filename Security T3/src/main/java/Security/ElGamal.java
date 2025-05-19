package Security;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;

public class ElGamal {

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
        BigInteger p     = BigInteger.valueOf(q);
        BigInteger a     = BigInteger.valueOf(alpha);
        BigInteger bigY  = BigInteger.valueOf(y);
        BigInteger bigK  = BigInteger.valueOf(k);
        BigInteger bigM  = BigInteger.valueOf(m);

        // c1 = alpha^k mod q
        BigInteger c1 = a.modPow(bigK, p);
        // c2 = m * y^k mod q
        BigInteger c2 = bigY.modPow(bigK, p).multiply(bigM).mod(p);

        return Arrays.asList(c1.longValue(), c2.longValue());
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
        BigInteger p    = BigInteger.valueOf(q);
        BigInteger bigC1 = BigInteger.valueOf(c1);
        BigInteger bigC2 = BigInteger.valueOf(c2);
        BigInteger bigX  = BigInteger.valueOf(x);

        // s = c1^x mod q
        BigInteger s = bigC1.modPow(bigX, p);
        // m = c2 * s^(-1) mod q
        BigInteger sInv = s.modInverse(p);
        BigInteger m    = bigC2.multiply(sInv).mod(p);

        return m.intValue();
    }

}
