package Security;
import java.util.*;

public class ColumnarCipher {

    public List<Integer> analyse(String plainText, String cipherText) {
        // TODO: Analyze the plainText and cipherText to determine the key(s)

        // We try candidate key lengths from 1 to the length of the plain text.
        int m = plainText.length(); //15
        // Work in upper case to avoid case mismatches.
        cipherText = cipherText.toUpperCase();
        plainText = plainText.toUpperCase();

        // Try every possible key length until we find one that produces the given cipher text.
        for (int keyLen = 1; keyLen <= m; keyLen++) {
            int rows = (int) Math.ceil((double) m / keyLen); // len(p.t)/len(k)(#cols)
            // Determine how many padding letters were added in encryption.
            int totalCells = rows * keyLen;
            int padCount = totalCells - m;  // number of padded characters appended at the end, assumed to be 'x'

            // Build the padded plain text (if necessary)
            StringBuilder paddedText = new StringBuilder(plainText);
            for (int i = 0; i < padCount; i++) {
                paddedText.append('X');  // use uppercase 'X' as in encrypt method
            }

            // Fill the grid row-wise.
            char[][] grid = new char[rows][keyLen];
            int index = 0;
            for (int i = 0; i < rows; i++) {
                for (int j = 0; j < keyLen; j++) {
                    grid[i][j] = paddedText.charAt(index++);
                }
            }

            // For each original column j, determine its "effective" string.
            // In the encryption (and decryption) methods, if there is a partial last row,
            // then for columns j that are in the right part of the grid, the last cell is not used.
            int remainder = m % keyLen; // if remainder==0 then every column gets all rows.
            String[] colStrings = new String[keyLen];
            for (int j = 0; j < keyLen; j++) {
                StringBuilder sb = new StringBuilder();
                for (int i = 0; i < rows; i++) {
                    // If we are in the last row and this column is one of those that would be padded,
                    // then skip it.
                    if (i == rows - 1 && remainder != 0 && j >= remainder)
                        break;
                    sb.append(grid[i][j]);
                }
                colStrings[j] = sb.toString();
            }

            // The encryption reads the columns in an order determined by the key:
            // concatenating columns in the “sorted order” of key digits.
            // We need to decide if there is a permutation (ordering) of the columns that when concatenated
            // equals the cipherText.
            List<Integer> permutation = findPermutation(colStrings, cipherText, keyLen);
            if (permutation != null) {
                // Build the key: for each original column (index j), its key digit is its position
                // (from the sorted order) plus one.
                // permutation.get(i) gives the original column index that appears in the i-th sorted position.
                List<Integer> key = new ArrayList<>(Collections.nCopies(keyLen, 0));
                for (int sortedIndex = 0; sortedIndex < keyLen; sortedIndex++) {
                    int origIndex = permutation.get(sortedIndex);
                    key.set(origIndex, sortedIndex + 1);
                }
                return key;
            }
        }
        // If no permutation was found, return an empty key.
        return new ArrayList<>();
    }

    // Backtracking helper: try to assign an order (a permutation) of column indices
    // such that concatenating colStrings in that order equals target.
    private List<Integer> findPermutation(String[] colStrings, String target, int keyLen) {
        boolean[] used = new boolean[keyLen];
        List<Integer> current = new ArrayList<>();
        List<Integer> result = backtrack(colStrings, target, current, used, keyLen);
        return result;
    }

    private List<Integer> backtrack(String[] colStrings, String target, List<Integer> current, boolean[] used, int keyLen) {
        if (current.size() == keyLen) {
            // Check if complete permutation gives the target cipher text.
            StringBuilder sb = new StringBuilder();
            for (int index : current) {
                sb.append(colStrings[index]);
            }
            if (sb.toString().equals(target))
                return new ArrayList<>(current);
            else
                return null;
        }
        // Pruning: build partial concatenation and check whether target starts with it.
        StringBuilder partialBuilder = new StringBuilder();
        for (int index : current) {
            partialBuilder.append(colStrings[index]);
        }
        String partial = partialBuilder.toString();
        if (!target.startsWith(partial))
            return null;

        for (int i = 0; i < keyLen; i++) {
            if (!used[i]) {
                used[i] = true;
                current.add(i);
                List<Integer> result = backtrack(colStrings, target, current, used, keyLen);
                if (result != null)
                    return result;
                current.remove(current.size() - 1);
                used[i] = false;
            }
        }
        return null;
    }




    public String decrypt(String cipherText, List<Integer> key) {
        int cipherSize = cipherText.length();
        int rows = (int) Math.ceil((double) cipherSize / key.size());
        char[][] grid = new char[rows][key.size()];
        int count = 0;

        Map<Integer, Integer> keyMap = new HashMap<>();
        for (int i = 0; i < key.size(); i++) {
            keyMap.put(key.get(i) - 1, i);
        }

        int remainingCols = cipherSize % key.size();
        for (int i = 0; i < key.size(); i++) {
            for (int j = 0; j < rows; j++) {
                if (remainingCols != 0 && j == rows - 1 && keyMap.get(i) >= remainingCols) continue;
                grid[j][keyMap.get(i)] = cipherText.charAt(count++);
            }
        }

        StringBuilder result = new StringBuilder();
        for (int i = 0; i < rows; i++) {
            for (int j = 0; j < key.size(); j++) {
                result.append(grid[i][j]);
            }
        }
        return result.toString().toUpperCase().trim();
    }

    public String encrypt(String plainText, List<Integer> key) {
        int ptSize = plainText.length();
        int rows = (int) Math.ceil((double) ptSize / key.size());
        char[][] grid = new char[rows][key.size()];
        int count = 0;

        for (int i = 0; i < rows; i++) {
            for (int j = 0; j < key.size(); j++) {
                if (count >= ptSize) {
                    grid[i][j] = 'x';
                } else {
                    grid[i][j] = plainText.charAt(count++);
                }
            }
        }

        Map<Integer, Integer> keyMap = new HashMap<>();
        for (int i = 0; i < key.size(); i++) {
            keyMap.put(key.get(i) - 1, i);
        }

        StringBuilder cipherText = new StringBuilder();
        for (int i = 0; i < key.size(); i++) {
            for (int j = 0; j < rows; j++) {
                cipherText.append(Character.toUpperCase(grid[j][keyMap.get(i)]));
            }
        }
        return cipherText.toString();
    }
}
