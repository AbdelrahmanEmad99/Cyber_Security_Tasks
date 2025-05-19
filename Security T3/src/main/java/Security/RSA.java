package Security;

import java.math.BigInteger;

public class RSA {

    /**
     * Encrypts a message M using RSA.
     * @param p   first prime
     * @param q   second prime
     * @param M   plaintext message (0 <= M < p*q)
     * @param e   public exponent (must be co-prime to phi(n))
     * @return    ciphertext C = M^e mod n
     */
    public int encrypt(int p, int q, int M, int e) {
        BigInteger bigP = BigInteger.valueOf(p);
        BigInteger bigQ = BigInteger.valueOf(q);
        BigInteger n    = bigP.multiply(bigQ);
        BigInteger message = BigInteger.valueOf(M);
        BigInteger exp = BigInteger.valueOf(e);

        // C = M^e mod n
        BigInteger C = message.modPow(exp, n);
        return C.intValue();
    }

    /**
     * Decrypts a ciphertext C using RSA.
     * @param p   first prime
     * @param q   second prime
     * @param C   ciphertext
     * @param e   public exponent (same e used during encryption)
     * @return    decrypted plaintext M = C^d mod n
     */
    public int decrypt(int p, int q, int C, int e) {
        BigInteger bigP = BigInteger.valueOf(p);
        BigInteger bigQ = BigInteger.valueOf(q);
        BigInteger n    = bigP.multiply(bigQ);

        // Compute phi(n) = (p-1)*(q-1)
        BigInteger phi = bigP.subtract(BigInteger.ONE)
                .multiply(bigQ.subtract(BigInteger.ONE));

        // Compute private exponent d ≡ e⁻¹ mod phi
        BigInteger exp = BigInteger.valueOf(e);
        BigInteger d = exp.modInverse(phi);

        BigInteger cipher = BigInteger.valueOf(C);

        // M = C^d mod n
        BigInteger M = cipher.modPow(d, n);
        return M.intValue();
    }


}
