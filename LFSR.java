import java.util.Scanner;

public class LFSR { 
    private int[] register; 
    private int[] taps;     

    // Compute feedback using XOR
    private int feedback() {
        int feedback = 0;
        for (int i = 0; i < taps.length; i++) {
            feedback ^= register[taps[i] - 1]; 
        }
        return feedback;
    }

    // Perform one LFSR step
    private int step() {
        int feedback = feedback();
        int shiftedOut = register[register.length - 1];
        for (int i = register.length - 1; i > 0; i--) {
            register[i] = register[i - 1];
        }
        register[0] = feedback;
        return shiftedOut;
    }

    // Generate sequence
    public String generateSequence(int length) {
        String seq = "";
        for (int i = 0; i < length; i++) {
            seq += step();
        }
        return seq;
    }

    // Cipher method
    public String cipher(String message, String keystream) {
        String ciphermsg = "";
        for (int i = 0; i < message.length(); i++) {
            int msgBit = message.charAt(i) - '0';
            int keyBit = keystream.charAt(i) - '0';
            ciphermsg += (msgBit ^ keyBit);
        }
        return ciphermsg;
    }

    public static void main(String[] args) {
        Scanner in = new Scanner(System.in);
        LFSR lfsr = new LFSR();

        // Seed input
        String seed;
        while (true) {
            System.out.println("Enter your initial seed: ");
            seed = in.next();
            if (!seed.matches("[01]+") || seed.matches("0+")) {
                System.out.println("Invalid! Seed must be binary and not all zeroes.");
            } else {
                break;
            }
        }
        
        int seedsize = seed.length();
        lfsr.register = new int[seedsize];
        for (int i = 0; i < seedsize; i++) {
            lfsr.register[i] = seed.charAt(i) - '0';
        }
        
        // Tap input
        int numtaps;
        do {
            System.out.println("Enter the number of tap positions (1 to " + seedsize + "): ");
            numtaps = in.nextInt();
            if (numtaps < 1 || numtaps > seedsize) {
                System.out.println("Invalid number of taps! Must be between 1 and " + seedsize);
            }
        } while (numtaps < 1 || numtaps > seedsize);

        lfsr.taps = new int[numtaps];
        System.out.println("Enter your tap positions (1 to " + seedsize + "): ");
        for (int i = 0; i < numtaps; i++) {
            while (true) {
                int tap = in.nextInt();
                if (tap < 1 || tap > seedsize) {
                    System.out.println("Invalid! Enter a number between 1 and " + seedsize);
                } else {
                    lfsr.taps[i] = tap;
                    break;
                }
            }
        }

        // Generate sequence
        String sequence = lfsr.generateSequence(100);
        System.out.println("100-bit sequence: " + sequence);

        // Cipher demo
        System.out.println("Enter a binary message to encrypt: ");
        String message;
        while (true) {
            message = in.next();
            if (message.matches("[01]+")) {
                break;
            }
            System.out.println("Invalid! Enter a binary message (only 0s and 1s).");
        }

        String keystream = sequence.substring(0, message.length());
        String ciphertext = lfsr.cipher(message, keystream);
        System.out.println("Ciphertext: " + ciphertext);
        String decrypted = lfsr.cipher(ciphertext, keystream);
        System.out.println("Decrypted: " + decrypted);

        in.close(); 
    }
}