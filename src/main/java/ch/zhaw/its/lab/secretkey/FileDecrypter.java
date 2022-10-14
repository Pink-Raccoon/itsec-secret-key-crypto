package ch.zhaw.its.lab.secretkey;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;

import static ch.zhaw.its.lab.secretkey.DatatypeConverter.printHexBinary;
import static ch.zhaw.its.lab.secretkey.FileEncrypter.CALGORITHM;
import static ch.zhaw.its.lab.secretkey.FileEncrypter.KALGORITHM;

public class FileDecrypter {
    final static int ARRAY_LENGTH = 256;
    final static double MAX_ENTROPY = 5.0;

    final static String FILE_INPUT = "mystery";
    final static String FILE_OUTPUT = "decrypted.txt";

    public static void main(String[] args) {
        // find out at what time the key gen has started

        byte[] byteArray = new byte[0];
        try {
            byteArray = Files.readAllBytes(Path.of(FILE_INPUT));
        } catch (IOException e) {
            System.err.printf("Unable to read input file: %s%n", FILE_INPUT);
        }

        long startTime = findStartTime(byteArray);
        System.out.printf("Starting time: %d%n", startTime);

        byte[] rawKey = generateKey(startTime);
        // generated key
        System.out.printf("Key:\t%s%n", printHexBinary(rawKey));

        for (long i = startTime; i > 0; i--) {
            try {
                byte[] key = generateKey(i);
                byte[] result = decrypt(byteArray, key);

                if (isNaturalLanguage(result)) {
                    System.out.printf("Time of creation: %d%n", i);
                    System.out.printf("Key:\t%s%n", printHexBinary(key));
                    OutputStream os = Files.newOutputStream(Paths.get(FILE_OUTPUT));
                    os.write(result);
                    os.close();
                    return;
                }
            } catch (Exception ignored) {
            }
        }
    }

    private static long findStartTime(byte[] bytes) {
        // find start time
        List<Integer> startBytes = new ArrayList<>();
        for (byte b : bytes) {
            int bb = Byte.toUnsignedInt(b);
            if (bb == 0x00) {
                break;
            }
            startBytes.add(bb);
        }
        long startTime = 0;
        for (int i = startBytes.size() - 1; i >= 0; i--) {
            startTime += startBytes.get(i);
            startTime <<= 8;
        }
        return startTime >> 8;
    }

    private static byte[] generateKey(long number) {
        byte[] bytes = new byte[16];
        for (int i = 0; i < bytes.length; i++) {
            bytes[i] = (byte) (number & 0xff);
            number >>= 8;
        }
        return bytes;
    }

    private static byte[] decrypt(byte[] cipherText, byte[] rawKey) throws NoSuchPaddingException, NoSuchAlgorithmException, IOException,
            BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException, InvalidKeyException {
        SecretKey key = new SecretKeySpec(rawKey, 0, rawKey.length, KALGORITHM);
        Cipher cipher = Cipher.getInstance(CALGORITHM);
        try (
                InputStream is = new ByteArrayInputStream(cipherText);
                ByteArrayOutputStream os = new ByteArrayOutputStream()
        ) {
            IvParameterSpec ivParameterSpec = readIv(is, cipher);
            cipher.init(Cipher.DECRYPT_MODE, key, ivParameterSpec);
            crypt(is, os, cipher);
            return os.toByteArray();
        }
    }

    public static void crypt(InputStream is, OutputStream os, Cipher cipher) throws IOException, BadPaddingException, IllegalBlockSizeException {
        byte[] input = new byte[cipher.getBlockSize()];

        while (true) {
            int inBytes = is.read(input);
            if (inBytes <= 0)
                break;
            os.write(cipher.update(input, 0, inBytes));
        }
        os.write(cipher.doFinal());
    }

    public static IvParameterSpec readIv(InputStream is, Cipher cipher) throws IOException {
        byte[] rawIv = new byte[cipher.getBlockSize()];
        int inBytes = is.read(rawIv);
        if (inBytes != cipher.getBlockSize()) {
            throw new IOException("can't read IV from file");
        }
        return new IvParameterSpec(rawIv);
    }

    private static boolean isNaturalLanguage(byte[] buffer) {
        int[] charCount = new int[ARRAY_LENGTH];
        double entropy = 0.0;
        for (byte b : buffer) {
            charCount[Byte.toUnsignedInt(b)]++;
        }
        for (int i = 0; i < ARRAY_LENGTH; i++) {
            double currFrequency = (double) charCount[i] / buffer.length;
            if (currFrequency != 0.0)
                entropy += currFrequency * log2(currFrequency);
        }
        return ((-1)*entropy) <= MAX_ENTROPY;
    }

    private static double log2(double N) {
        return (Math.log(N) / Math.log(2));
    }
}
