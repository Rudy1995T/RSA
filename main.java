package rsacryptography;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Scanner;

public class RSA
{

    public void generateKeys()
    {
        final int BIT_LENGTH = 1024;
        BigInteger one = BigInteger.ONE;

        SecureRandom randP = new SecureRandom();
        SecureRandom randQ = new SecureRandom();
        SecureRandom randE = new SecureRandom();

        // Generate two large random p & q primes and check both are distinct.
        BigInteger p, q;
        do
        {
            p = BigInteger.probablePrime(BIT_LENGTH, randP);
            q = BigInteger.probablePrime(BIT_LENGTH, randQ);
        } while (p.compareTo(q) == 0);

        // Compute n = pq
        BigInteger n = p.multiply(q);

        // Compute φ(n) = (p-1)(q-1)
        BigInteger phiNumOfN = p.subtract(one).multiply(q.subtract(one));

        // Destory p and q;
        p = one;
        q = one;

        // Compute e, 1 < e < φ(n) and gcd (e, φ(n)) = 1 
        
        BigInteger e;
        
        do
        {
            e = BigInteger.probablePrime(BIT_LENGTH, randE);
        } while (e.compareTo(phiNumOfN) >= 0 && (e.gcd(phiNumOfN).compareTo(one) == 0));

        // Compute d, 1 < d φ(n) and ed mod n = 1 mod n (inverse)
        
        BigInteger d;
        do
        {
            d = e.modInverse(phiNumOfN);
        } while (d.compareTo(phiNumOfN) >= 0 && ((e.multiply(d)).mod(n)).compareTo(one) != 0);

        // Destroy φ(n)
        phiNumOfN = one;

        try (PrintWriter pubKeyStorage = new PrintWriter("./RSAPublicKey.txt"))
        {
            pubKeyStorage.println(e + " " + n);
            pubKeyStorage.flush();
            pubKeyStorage.close();
        } catch (FileNotFoundException err)
        {
            System.out.println(err);
        }

        try (PrintWriter privKeyStorage = new PrintWriter("./RSAPrivateKey.txt"))
        {
            privKeyStorage.println(d + " " + n);
            privKeyStorage.flush();
            privKeyStorage.close();
        } catch (FileNotFoundException err)
        {
            System.out.println(err);
        }
    }
  

    public BigInteger encrypt(String mPlain)
    {
        File key = new File("./RSAPublicKey.txt");
        Scanner in;
        BigInteger e = BigInteger.ZERO;
        BigInteger n = BigInteger.ZERO;
        try
        {
            in = new Scanner(key);
            e = in.nextBigInteger();
            n = in.nextBigInteger();
        }
        catch (FileNotFoundException err)
        {
            System.out.println(err);
        }
         
        BigInteger M = new BigInteger(mPlain.getBytes());
        BigInteger C = M.modPow(e, n);
        return C;
    }

    public String decrypt(BigInteger C)
    {
        File key = new File("./RSAPrivateKey.txt");
        Scanner in;
        BigInteger d = BigInteger.ZERO;
        BigInteger n = BigInteger.ZERO;
        try
        {
            in = new Scanner(key);
            d = in.nextBigInteger();
            n = in.nextBigInteger();
        }
        catch (FileNotFoundException err)
        {
            System.out.println(err);
        }
        
        BigInteger M = C.modPow(d, n);
        String mPlain = new String(M.toByteArray());
        return mPlain;
    }

    public void run() throws InterruptedException
    {
        
        // Validation - signifies amount of characters RSA can handle, depends on bit length of N.
        int maxMessageCharLength = (1024 / 4) - 1;

        Scanner keyboardIn = new Scanner(System.in);
        String option = "";

        while (!"0".equals(option))
        {
            String message = "";
            int messageCharLength;

            // User input and validation
            do
            {
                System.out.print("Bob - Insert Message (at most " + maxMessageCharLength + " characters): ");
                message = keyboardIn.nextLine();

                // Get byte length of string.
                messageCharLength = message.getBytes().length;

                // Alerts user if message byte size too big/greater than byte size of N.
                if (messageCharLength > maxMessageCharLength)
                {
                    System.err.println("Message has " + message.getBytes().length + " characters. Maximum amount is " + maxMessageCharLength + ".");
                } // Alerts user if message is empty.
                else if (messageCharLength < 1)
                {
                    System.err.println("Message must have at least one character.");
                }
            } // Must must be at least 1 character and not bigger than N
            while (messageCharLength < 1 || messageCharLength > maxMessageCharLength);

            System.out.println("Bob - encrypting message...");

            BigInteger C = encrypt(message);

            System.out.println("Message encrypted and sent to Alice...");
            System.out.println("---");

            Thread.sleep(1000);

            System.out.println("Alice receives C from Bob and decrypts it...");

            String M = decrypt(C);

            System.out.println("Alice sees the message in plaintext: " + "\"" + M + "\"");
            System.out.println("---");

            Thread.sleep(1000);

            System.out.print("Try again? Type 0 to exit or anything else to continue: ");
            option = keyboardIn.nextLine();

        }
        System.out.println("Exiting...");
    }

    public static void main(String[] args) throws InterruptedException
    {
        RSA rsa = new RSA();
        rsa.run();
    }
}
