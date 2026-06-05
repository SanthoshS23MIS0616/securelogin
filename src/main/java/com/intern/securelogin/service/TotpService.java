package com.intern.securelogin.service;

import java.io.ByteArrayOutputStream;
import java.net.URLEncoder;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.stereotype.Service;

@Service
public class TotpService {

    private static final String BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    private static final int CODE_DIGITS = 6;
    private static final long TIME_STEP_SECONDS = 30L;
    private static final String ISSUER = "SecureLogin";

    private final SecureRandom secureRandom = new SecureRandom();

    public String generateSecret() {
        byte[] bytes = new byte[20];
        secureRandom.nextBytes(bytes);
        return base32Encode(bytes);
    }

    public boolean isValidCode(String secret, String code) {
        if (secret == null || code == null || !code.matches("^\\d{6}$")) {
            return false;
        }

        long currentStep = System.currentTimeMillis() / 1000L / TIME_STEP_SECONDS;
        for (long offset = -1; offset <= 1; offset++) {
            String expected = generateCode(secret, currentStep + offset);
            if (MessageDigest.isEqual(expected.getBytes(StandardCharsets.UTF_8), code.getBytes(StandardCharsets.UTF_8))) {
                return true;
            }
        }
        return false;
    }

    public String buildOtpAuthUri(String email, String secret) {
        String label = URLEncoder.encode(ISSUER + ":" + email, StandardCharsets.UTF_8);
        String issuer = URLEncoder.encode(ISSUER, StandardCharsets.UTF_8);
        return "otpauth://totp/" + label + "?secret=" + secret + "&issuer=" + issuer + "&digits=6&period=30";
    }

    String generateCode(String secret, long timeStep) {
        try {
            byte[] key = base32Decode(secret);
            byte[] data = ByteBuffer.allocate(8).putLong(timeStep).array();
            Mac mac = Mac.getInstance("HmacSHA1");
            mac.init(new SecretKeySpec(key, "HmacSHA1"));
            byte[] hash = mac.doFinal(data);
            int offset = hash[hash.length - 1] & 0x0f;
            int binary = ((hash[offset] & 0x7f) << 24)
                | ((hash[offset + 1] & 0xff) << 16)
                | ((hash[offset + 2] & 0xff) << 8)
                | (hash[offset + 3] & 0xff);
            int otp = binary % 1_000_000;
            return String.format("%0" + CODE_DIGITS + "d", otp);
        } catch (GeneralSecurityException ex) {
            throw new IllegalStateException("Could not generate authenticator code", ex);
        }
    }

    private String base32Encode(byte[] bytes) {
        StringBuilder encoded = new StringBuilder();
        int buffer = 0;
        int bitsLeft = 0;
        for (byte current : bytes) {
            buffer = (buffer << 8) | (current & 0xff);
            bitsLeft += 8;
            while (bitsLeft >= 5) {
                encoded.append(BASE32_ALPHABET.charAt((buffer >> (bitsLeft - 5)) & 31));
                bitsLeft -= 5;
            }
        }
        if (bitsLeft > 0) {
            encoded.append(BASE32_ALPHABET.charAt((buffer << (5 - bitsLeft)) & 31));
        }
        return encoded.toString();
    }

    private byte[] base32Decode(String secret) {
        String normalized = secret.replace(" ", "").replace("=", "").toUpperCase();
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        int buffer = 0;
        int bitsLeft = 0;

        for (char current : normalized.toCharArray()) {
            int value = BASE32_ALPHABET.indexOf(current);
            if (value < 0) {
                throw new IllegalArgumentException("Invalid authenticator secret");
            }
            buffer = (buffer << 5) | value;
            bitsLeft += 5;
            if (bitsLeft >= 8) {
                output.write((buffer >> (bitsLeft - 8)) & 0xff);
                bitsLeft -= 8;
                buffer &= bitsLeft == 0 ? 0 : (1 << bitsLeft) - 1;
            }
        }

        return output.toByteArray();
    }
}
