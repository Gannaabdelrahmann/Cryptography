import java.util.Scanner;

public class AES {

    // AES constants - used in encryption/decryption methods
    private static final int BLOCK_SIZE = 16; // 128 bits
    private static final int NUMBER_OF_COLUMNS = 4; // Number of columns (32-bit words) comprising the State
    private static final int KEY_WORD_COUNT = 4; // Number of 32-bit words comprising the Cipher Key (128 bits)
    private static final int NUMBER_OF_ROUNDS = 10; // Number of rounds for AES-128

    // Round constants for key expansion
    private static final int[] rcon = {
        0x01000000, 0x02000000, 0x04000000, 0x08000000,
        0x10000000, 0x20000000, 0x40000000, 0x80000000,
        0x1b000000, 0x36000000
    };

    // S-box
    private static final int[] SBOX = {
        // (unchanged - same as your original, omitted here for brevity)
    };

    // Inverse S-box
    private static final int[] INVERSE_SBOX = {
        // (unchanged - same as your original, omitted here for brevity)
    };

    // State matrix (4x4) for AES operations
    private final byte[][] state = new byte[NUMBER_OF_COLUMNS][NUMBER_OF_COLUMNS];

    // Key expansion result
    private int[] expandedKey;

    // Constructor
    public AES(byte[] key) {
        if (key.length != BLOCK_SIZE) {
            throw new IllegalArgumentException("Key must be 128 bits (16 bytes)");
        }
        expandedKey = keyExpansion(key);
    }

    // Key expansion for AES-128
    private int[] keyExpansion(byte[] key) {
        int[] w = new int[NUMBER_OF_COLUMNS * (NUMBER_OF_ROUNDS + 1)];
        int temp;

        for (int i = 0; i < KEY_WORD_COUNT; i++) {
            w[i] = ((key[4 * i] & 0xff) << 24) | ((key[4 * i + 1] & 0xff) << 16) |
                   ((key[4 * i + 2] & 0xff) << 8) | (key[4 * i + 3] & 0xff);
        }

        for (int i = KEY_WORD_COUNT; i < w.length; i++) {
            temp = w[i - 1];
            if (i % KEY_WORD_COUNT == 0) {
                temp = subWord(rotWord(temp)) ^ rcon[i / KEY_WORD_COUNT - 1];
            }
            w[i] = w[i - KEY_WORD_COUNT] ^ temp;
        }
        return w;
    }

    // Helper function for key expansion
    private int subWord(int word) {
        return ((SBOX[(word >> 24) & 0xff] & 0xff) << 24) |
               ((SBOX[(word >> 16) & 0xff] & 0xff) << 16) |
               ((SBOX[(word >> 8) & 0xff] & 0xff) << 8) |
               (SBOX[word & 0xff] & 0xff);
    }

    private int rotWord(int word) {
        return ((word << 8) & 0xffffff00) | ((word >> 24) & 0xff);
    }

    // Add round key
    private void addRoundKey(int round) {
        int roundKeyIndex = round * NUMBER_OF_COLUMNS;
        for (int i = 0; i < NUMBER_OF_COLUMNS; i++) {
            for (int j = 0; j < NUMBER_OF_COLUMNS; j++) {
                state[j][i] = (byte) (state[j][i] ^ ((expandedKey[roundKeyIndex + i] >> (24 - 8 * j)) & 0xff));
            }
        }
    }

    // SubBytes transformation
    private void subBytes() {
        for (int i = 0; i < NUMBER_OF_COLUMNS; i++) {
            for (int j = 0; j < NUMBER_OF_COLUMNS; j++) {
                state[i][j] = (byte) SBOX[(state[i][j] & 0xff)];
            }
        }
    }

    // Inverse SubBytes transformation
    private void invSubBytes() {
        for (int i = 0; i < NUMBER_OF_COLUMNS; i++) {
            for (int j = 0; j < NUMBER_OF_COLUMNS; j++) {
                state[i][j] = (byte) INVERSE_SBOX[(state[i][j] & 0xff)];
            }
        }
    }

    // ShiftRows transformation
    private void shiftRows() {
        byte temp;
        for (int i = 1; i < NUMBER_OF_COLUMNS; i++) {
            for (int j = 0; j < i; j++) {
                temp = state[i][0];
                for (int k = 0; k < NUMBER_OF_COLUMNS - 1; k++) {
                    state[i][k] = state[i][k + 1];
                }
                state[i][NUMBER_OF_COLUMNS - 1] = temp;
            }
        }
    }

    // Inverse ShiftRows transformation
    private void invShiftRows() {
        byte temp;
        for (int i = 1; i < NUMBER_OF_COLUMNS; i++) {
            for (int j = 0; j < i; j++) {
                temp = state[i][NUMBER_OF_COLUMNS - 1];
                for (int k = NUMBER_OF_COLUMNS - 1; k > 0; k--) {
                    state[i][k] = state[i][k - 1];
                }
                state[i][0] = temp;
            }
        }
    }

    // MixColumns transformation
    private void mixColumns() {
        for (int i = 0; i < NUMBER_OF_COLUMNS; i++) {
            byte[] a = new byte[NUMBER_OF_COLUMNS];
            for (int j = 0; j < NUMBER_OF_COLUMNS; j++) {
                a[j] = state[j][i];
            }
            state[0][i] = (byte) (gfMul(0x02, a[0]) ^ gfMul(0x03, a[1]) ^ a[2] ^ a[3]);
            state[1][i] = (byte) (a[0] ^ gfMul(0x02, a[1]) ^ gfMul(0x03, a[2]) ^ a[3]);
            state[2][i] = (byte) (a[0] ^ a[1] ^ gfMul(0x02, a[2]) ^ gfMul(0x03, a[3]));
            state[3][i] = (byte) (gfMul(0x03, a[0]) ^ a[1] ^ a[2] ^ gfMul(0x02, a[3]));
        }
    }

    // Inverse MixColumns transformation
    private void invMixColumns() {
        for (int i = 0; i < NUMBER_OF_COLUMNS; i++) {
            byte[] a = new byte[NUMBER_OF_COLUMNS];
            for (int j = 0; j < NUMBER_OF_COLUMNS; j++) {
                a[j] = state[j][i];
            }
            state[0][i] = (byte) (gfMul(0x0e, a[0]) ^ gfMul(0x0b, a[1]) ^ gfMul(0x0d, a[2]) ^ gfMul(0x09, a[3]));
            state[1][i] = (byte) (gfMul(0x09, a[0]) ^ gfMul(0x0e, a[1]) ^ gfMul(0x0b, a[2]) ^ gfMul(0x0d, a[3]));
            state[2][i] = (byte) (gfMul(0x0d, a[0]) ^ gfMul(0x09, a[1]) ^ gfMul(0x0e, a[2]) ^ gfMul(0x0b, a[3]));
            state[3][i] = (byte) (gfMul(0x0b, a[0]) ^ gfMul(0x0d, a[1]) ^ gfMul(0x09, a[2]) ^ gfMul(0x0e, a[3]));
        }
    }

    // Galois Field multiplication
    private byte gfMul(int a, byte b) {
        int p = 0;
        int bInt = b & 0xff;
        for (int i = 0; i < 8; i++) {
            if ((bInt & 0x01) != 0) p ^= a;
            boolean highBitSet = (a & 0x80) != 0;
            a <<= 1;
            if (highBitSet) a ^= 0x1b;
            a &= 0xff;
            bInt >>= 1;
        }
        return (byte) (p & 0xff);
    }

    // Encrypt a single block
    public byte[] encrypt(byte[] input) {
        if (input.length != BLOCK_SIZE) throw new IllegalArgumentException("Input must be 128 bits (16 bytes)");

        for (int i = 0; i < NUMBER_OF_COLUMNS; i++) {
            for (int j = 0; j < NUMBER_OF_COLUMNS; j++) {
                state[j][i] = input[i * NUMBER_OF_COLUMNS + j];
            }
        }

        addRoundKey(0);
        for (int round = 1; round < NUMBER_OF_ROUNDS; round++) {
            subBytes();
            shiftRows();
            mixColumns();
            addRoundKey(round);
        }
        subBytes();
        shiftRows();
        addRoundKey(NUMBER_OF_ROUNDS);

        byte[] output = new byte[BLOCK_SIZE];
        for (int i = 0; i < NUMBER_OF_COLUMNS; i++) {
            for (int j = 0; j < NUMBER_OF_COLUMNS; j++) {
                output[i * NUMBER_OF_COLUMNS + j] = state[j][i];
            }
        }
        return output;
    }

    // Decrypt a single block
    public byte[] decrypt(byte[] input) {
        if (input.length != BLOCK_SIZE) throw new IllegalArgumentException("Input must be 128 bits (16 bytes)");

        for (int i = 0; i < NUMBER_OF_COLUMNS; i++) {
            for (int j = 0; j < NUMBER_OF_COLUMNS; j++) {
                state[j][i] = input[i * NUMBER_OF_COLUMNS + j];
            }
        }

        addRoundKey(NUMBER_OF_ROUNDS);
        for (int round = NUMBER_OF_ROUNDS - 1; round > 0; round--) {
            invShiftRows();
            invSubBytes();
            addRoundKey(round);
            invMixColumns();
        }
        invShiftRows();
        invSubBytes();
        addRoundKey(0);

        byte[] output = new byte[BLOCK_SIZE];
        for (int i = 0; i < NUMBER_OF_COLUMNS; i++) {
            for (int j = 0; j < NUMBER_OF_COLUMNS; j++) {
                output[i * NUMBER_OF_COLUMNS + j] = state[j][i];
            }
        }
        return output;
    }

    // Helper method to convert hex string to byte array
    private static byte[] hexStringToByteArray(String hex) {
        if (hex.length() % 2 != 0) {
            throw new IllegalArgumentException("Hex string must have an even length");
        }
        byte[] bytes = new byte[hex.length() / 2];
        for (int i = 0; i < hex.length(); i += 2) {
            bytes[i / 2] = (byte) Integer.parseInt(hex.substring(i, i + 2), 16);
        }
        return bytes;
    }

    // Helper method to convert byte array to hex string
    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    // Main method to test AES
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);

        try {
            System.out.println("Enter a 128-bit key as a 32-character hexadecimal string:");
            String keyHex = scanner.nextLine().trim();
            if (keyHex.length() != 32 || !keyHex.matches("[0-9A-Fa-f]+")) {
                throw new IllegalArgumentException("Key must be a 32-character hexadecimal string");
            }
            byte[] key = hexStringToByteArray(keyHex);

            System.out.println("Enter a 128-bit plaintext as a 32-character hexadecimal string:");
            String plaintextHex = scanner.nextLine().trim();
            if (plaintextHex.length() != 32 || !plaintextHex.matches("[0-9A-Fa-f]+")) {
                throw new IllegalArgumentException("Plaintext must be a 32-character hexadecimal string");
            }
            byte[] plaintext = hexStringToByteArray(plaintextHex);

            AES aes = new AES(key);
            byte[] ciphertext = aes.encrypt(plaintext);
            System.out.println("Plaintext:  " + plaintextHex.toLowerCase());
            System.out.println("Ciphertext: " + bytesToHex(ciphertext));

            byte[] decrypted = aes.decrypt(ciphertext);
            System.out.println("Decrypted:  " + bytesToHex(decrypted));

            boolean matches = true;
            for (int i = 0; i < plaintext.length; i++) {
                if (plaintext[i] != decrypted[i]) {
                    matches = false;
                    break;
                }
            }
            System.out.println("Decryption successful: " + matches);
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
        } finally {
            scanner.close();
        }
    }
}
