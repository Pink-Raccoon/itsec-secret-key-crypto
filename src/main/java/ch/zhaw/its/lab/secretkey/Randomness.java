package ch.zhaw.its.lab.secretkey;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;

public class Randomness {
    final static int ARRAY_LENGTH = 256;

    final static String FILE_INPUT = "src\\main\\java\\ch\\zhaw\\its\\lab\\secretkey\\FileEncrypter.java";

    public static void main(String[] args) throws IOException {
        byte[] byteArray = new byte[0];
        try {
            byteArray = Files.readAllBytes(Path.of(FILE_INPUT));
        } catch (IOException e) {
            System.err.printf("Unable to read input file: %s%n", FILE_INPUT);
        }
        calcFileEntropy (byteArray);
    }

    private static void calcFileEntropy(byte[] buffer) {
        int[] charCount = new int[ARRAY_LENGTH];
        double entropy = 0.0;
        for (byte b : buffer) {
            charCount[b & 0xFF]++;
        }
        for (int i = 0; i < ARRAY_LENGTH; i++) {
            double currFrequency = (double) charCount[i] / buffer.length;
            if (currFrequency != 0.0)
                entropy += currFrequency * log2(currFrequency);
        }
        double result = (-1) * entropy;
        System.out.println(result);
    }

    private static double log2(double N) {
        return (Math.log(N) / Math.log(2));
    }
}
