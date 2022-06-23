package com.imom.crypto.util;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

public class PasswordGenerator {
    private static final String CHAR_LOWERCASE = "abcdefghjkmnpqrstuvwxyz";
    private static final String CHAR_UPPERCASE = CHAR_LOWERCASE.toUpperCase();
    private static final String DIGIT = "23456789";
    private static final String OTHER_PUNCTUATION = "!@#&()–[{}]:;',?/*";
    private static final String OTHER_SYMBOL = "~$^+=<>";
    private static final String OTHER_SPECIAL = OTHER_PUNCTUATION + OTHER_SYMBOL;
    private static final int PASSWORD_LENGTH = 16;

    private static final String PASSWORD_ALLOW =
            CHAR_LOWERCASE + CHAR_UPPERCASE + DIGIT;

    private static final SecureRandom random = new SecureRandom();

    private PasswordGenerator() {}

    public static String generateStrongPassword() {
        StringBuilder result = new StringBuilder(PASSWORD_LENGTH);

        // at least 6 chars (lowercase)
        String strLowerCase = generateRandomString(CHAR_LOWERCASE, 6);
        result.append(strLowerCase);

        // at least 2 chars (uppercase)
        String strUppercaseCase = generateRandomString(CHAR_UPPERCASE, 2);
        result.append(strUppercaseCase);

        // at least 3 digits
        String strDigit = generateRandomString(DIGIT, 3);
        result.append(strDigit);

        // remaining, just random
        String strOther = generateRandomString(PASSWORD_ALLOW, PASSWORD_LENGTH - 11);
        result.append(strOther);

        return shuffleString(result.toString());

    }

    private static String generateRandomString(String input, int size) {

        if (input == null || input.length() <= 0)
            throw new IllegalArgumentException("Invalid input.");
        if (size < 1) throw new IllegalArgumentException("Invalid size.");

        StringBuilder result = new StringBuilder(size);
        for (int i = 0; i < size; i++) {
            // produce a random order
            int index = random.nextInt(input.length());
            result.append(input.charAt(index));
        }
        return result.toString();
    }

    // for final password, make it more random
    public static String shuffleString(String input) {
        List<String> result = Arrays.asList(input.split(""));
        Collections.shuffle(result);
        return result.stream().collect(Collectors.joining());
    }


}
