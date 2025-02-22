package Security;

import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.Set;

public class PlayfairCipher {
    private final char[][] keyMatrix;

    public PlayfairCipher(String key) {
        keyMatrix = generateKeyMatrix(key);
    }

    // Generates the 5x5 key matrix for Playfair Cipher
    private char[][] generateKeyMatrix(String key) {
        Set<Character> used = new LinkedHashSet<>();
        key = key.toUpperCase().replaceAll("[^A-Z]", "").replace("J", "I");

        for (char c : key.toCharArray()) {
            used.add(c);
        }

        for (char c = 'A'; c <= 'Z'; c++) {
            if (c != 'J') used.add(c);
        }

        char[][] matrix = new char[5][5];
        Iterator<Character> it = used.iterator();
        for (int i = 0; i < 5; i++) {
            for (int j = 0; j < 5; j++) {
                matrix[i][j] = it.next();
            }
        }
        return matrix;
    }

    // Prepares the text by removing invalid characters, replacing 'J' with 'I', and ensuring even length
    private String prepareText(String text) {
        text = text.toUpperCase().replaceAll("[^A-Z]", "").replace("J", "I");
        StringBuilder sb = new StringBuilder();

        for (int i = 0; i < text.length(); i++) {
            sb.append(text.charAt(i));
            // Insert 'X' if two consecutive letters are the same
            if (i < text.length() - 1 && text.charAt(i) == text.charAt(i + 1) && text.charAt(i) != 'X') {
                sb.append('X');
            }
        }
        // Ensure even length
        if (sb.length() % 2 != 0) {
            sb.append('X');
        }
        return sb.toString();
    }

    // TODO: Implement this method to find the position of a character in the key matrix
    private int[] findPosition(char c) {
        // Students should complete this part
        for(int i=0 ; i<5;i++){
            for(int j=0;j<5;j++){
                if(keyMatrix[i][j]==c){
                    return new int[]{i, j};
                }

            }
        }
        return null;
    }

    // Encrypts the given plaintext using the Playfair cipher algorithm
    public String encrypt(String text) {
        text = prepareText(text);
        StringBuilder encryptedText = new StringBuilder();

        for (int i = 0; i < text.length(); i += 2) {
            int[] pos1 = findPosition(text.charAt(i));
            int[] pos2 = findPosition(text.charAt(i + 1));

            if (pos1 == null || pos2 == null) continue; // Safety check

            if (pos1[0] == pos2[0]) {  // Same row >> shift right
                encryptedText.append(keyMatrix[pos1[0]][(pos1[1] + 1) % 5]);
                encryptedText.append(keyMatrix[pos2[0]][(pos2[1] + 1) % 5]);
            } else if (pos1[1] == pos2[1]) {  // Same column >> shift down
                encryptedText.append(keyMatrix[(pos1[0] + 1) % 5][pos1[1]]);
                encryptedText.append(keyMatrix[(pos2[0] + 1) % 5][pos2[1]]);
            } else {  // Rectangle swap >> intersection along row
                encryptedText.append(keyMatrix[pos1[0]][pos2[1]]);
                encryptedText.append(keyMatrix[pos2[0]][pos1[1]]);
            }
        }
        return encryptedText.toString();
    }

    private String removePadding(String text) {
        StringBuilder result = new StringBuilder();

        for (int i = 0; i < text.length(); i++) {
            // Don't add 'X' if it's an artificial padding
            if (i > 0 && text.charAt(i) == 'X' &&
                    (i == text.length() - 1 || text.charAt(i - 1) == text.charAt(i + 1))) {
                continue;
            }
            result.append(text.charAt(i));
        }
        return result.toString();
    }

    // TODO: Implement this method to decrypt the ciphertext back to plaintext
    public String decrypt(String text) {
        StringBuilder decryptedText = new StringBuilder();

        for (int i = 0; i < text.length(); i += 2) {
            int[] pos1 = findPosition(text.charAt(i));
            int[] pos2 = findPosition(text.charAt(i + 1));

            if (pos1 == null || pos2 == null) continue; // Safety check

            if (pos1[0] == pos2[0]) {  // Same row >> shift left
                decryptedText.append(keyMatrix[pos1[0]][(pos1[1] + 4) % 5]);
                decryptedText.append(keyMatrix[pos2[0]][(pos2[1] + 4) % 5]);
            } else if (pos1[1] == pos2[1]) {  // Same column >> shift up
                decryptedText.append(keyMatrix[(pos1[0] + 4) % 5][pos1[1]]);
                decryptedText.append(keyMatrix[(pos2[0] + 4) % 5][pos2[1]]);
            } else {  // Rectangle swap
                decryptedText.append(keyMatrix[pos1[0]][pos2[1]]);
                decryptedText.append(keyMatrix[pos2[0]][pos1[1]]);
            }
        }

        // Post-processing: Remove unnecessary 'X' that were added during encryption
        String result = decryptedText.toString();
        return removePadding(result);
    }

}
