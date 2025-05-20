package Security;

public class RSA {

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

    public int encrypt(int p, int q, int M, int e) {
        long n = (long) p * q;
        return (int) modPow(M, e, n);
    }

    public int decrypt(int p, int q, int C, int e) {
        long n = (long) p * q;
        long phi = (long) (p - 1) * (q - 1);
        long d = modInverse(e, phi);
        return (int) modPow(C, d, n);
    }
}
