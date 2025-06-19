import java.math.BigInteger;
import java.util.Random;
import java.util.Scanner;

public class RSA {

    // Miller-Rabin primality test
    public static boolean isPrime(long n, int k) {
        if (n < 2) return false;
        if (n == 2 || n == 3) return true;
        if (n % 2 == 0) return false;

        long r = 0;
        long d = n - 1;

        while (d % 2 == 0) {
            d /= 2;
            r++;
        }

        Random rand = new Random();

        for (int i = 0; i < k; i++) {
            long a = 2 + Math.abs(rand.nextLong()) % (n - 3);
            BigInteger x = BigInteger.valueOf(a).modPow(BigInteger.valueOf(d), BigInteger.valueOf(n));
            if (x.equals(BigInteger.ONE) || x.equals(BigInteger.valueOf(n - 1))) {
                continue;
            }

            boolean continueOuter = false;
            for (long j = 0; j < r - 1; j++) {
                x = x.modPow(BigInteger.valueOf(2), BigInteger.valueOf(n));
                if (x.equals(BigInteger.valueOf(n - 1))) {
                    continueOuter = true;
                    break;
                }
            }
            if (continueOuter) continue;

            return false; // composite
        }
        return true; // probably prime
    }

    // Generate key pair from primes p and q
    public static BigInteger[][] generateKeypair(long pLong, long qLong) {
        if (!isPrime(pLong, 10) || !isPrime(qLong, 10)) {
            throw new IllegalArgumentException("Both numbers must be prime.");
        }
        if (pLong == qLong) {
            throw new IllegalArgumentException("p and q cannot be the same.");
        }

        BigInteger p = BigInteger.valueOf(pLong);
        BigInteger q = BigInteger.valueOf(qLong);

        BigInteger n = p.multiply(q);
        BigInteger phi = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));

        // Choose e: 1 < e < phi and gcd(e, phi) = 1
        BigInteger e = BigInteger.valueOf(3);
        while (!e.gcd(phi).equals(BigInteger.ONE)) {
            e = e.add(BigInteger.TWO);
            if (e.compareTo(phi) >= 0) {
                throw new IllegalArgumentException("No suitable e found.");
            }
        }

        // Compute d, modular inverse of e mod phi
        BigInteger d = e.modInverse(phi);

        // Return keys: public key [e, n], private key [d, n]
        return new BigInteger[][] { { e, n }, { d, n } };
    }

    // Encrypt plaintext using public key
    public static BigInteger[] encrypt(BigInteger[] publicKey, String plaintext) {
        BigInteger e = publicKey[0];
        BigInteger n = publicKey[1];
        BigInteger[] cipher = new BigInteger[plaintext.length()];
        for (int i = 0; i < plaintext.length(); i++) {
            BigInteger m = BigInteger.valueOf(plaintext.charAt(i));
            cipher[i] = m.modPow(e, n);
        }
        return cipher;
    }

    // Decrypt ciphertext using private key
    public static String decrypt(BigInteger[] privateKey, BigInteger[] ciphertext) {
        BigInteger d = privateKey[0];
        BigInteger n = privateKey[1];
        StringBuilder plain = new StringBuilder();
        for (BigInteger c : ciphertext) {
            BigInteger m = c.modPow(d, n);
            plain.append((char) m.intValue());
        }
        return plain.toString();
    }

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        try {
            System.out.print("Enter prime number p: ");
            long p = scanner.nextLong();

            System.out.print("Enter prime number q: ");
            long q = scanner.nextLong();

            BigInteger[][] keys = generateKeypair(p, q);
            BigInteger[] publicKey = keys[0];
            BigInteger[] privateKey = keys[1];

            System.out.println("Public key: [" + publicKey[0] + ", " + publicKey[1] + "]");
            System.out.println("Private key: [" + privateKey[0] + ", " + privateKey[1] + "]");

            scanner.nextLine(); // consume leftover newline

            System.out.print("Enter message to encrypt: ");
            String message = scanner.nextLine();

            System.out.println("Original message: " + message);

            BigInteger[] encryptedMsg = encrypt(publicKey, message);
            System.out.print("Encrypted message: ");
            for (BigInteger c : encryptedMsg) {
                System.out.print(c + " ");
            }
            System.out.println();

            String decryptedMsg = decrypt(privateKey, encryptedMsg);
            System.out.println("Decrypted message: " + decryptedMsg);

        } catch (IllegalArgumentException e) {
            System.out.println("Error: " + e.getMessage());
        } finally {
            scanner.close();
        }
    }
}
