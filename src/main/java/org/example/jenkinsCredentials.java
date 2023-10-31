package org.example;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


public class jenkinsCredentials {
    public static void main(String[] args) {
        String jenkinsHome = System.getenv("JENKINS_HOME");
        if (jenkinsHome == null || jenkinsHome.isEmpty()) {
            System.err.println("JENKINS_HOME environment variable not set.");
            System.exit(1);
        }
        if (args.length < 2 || !args[0].equals("-m")) {
            System.exit(1);
        }

        String mode = args[1];

        if (mode.equals("ssh")) {
            decryptSSH(jenkinsHome);
        } else {
            System.out.println("Unknown mode: " + mode);
            System.exit(1);
        }
    }
    public static void decryptSSH(String jenkinsHome){

        String masterKeyPath = Paths.get(jenkinsHome, "secrets", "master.key").toString();
        String hudsonSecretKeyPath = Paths.get(jenkinsHome, "secrets", "hudson.util.Secret").toString();

        try {
            byte[] masterKey = Files.readAllBytes(Paths.get(masterKeyPath));
            byte[] hudsonSecretKey = Files.readAllBytes(Paths.get(hudsonSecretKeyPath));
            byte[] hashedMasterKey = getHashedMasterKey(masterKey);
            byte[] decryptedData = decryptAES(hashedMasterKey, hudsonSecretKey);
            byte[] secretPart = Arrays.copyOfRange(decryptedData, 0, 16);

            String xmlContent = new String(Files.readAllBytes(Paths.get(jenkinsHome,"jenkins.plugins.publish_over_ssh.BapSshPublisherPlugin.xml")));

            List<String> usernames = extractUsingRegex(xmlContent, "<username>(.*?)</username>");
            List<String> passwords = extractUsingRegex(xmlContent, "<jenkins\\.plugins\\.publish__over__ssh\\.BapSshHostConfiguration>.*?<secretPassphrase>\\{(.*?)\\}</secretPassphrase>");
            List<String> names = extractUsingRegex(xmlContent, "<name>(.*?)</name>");
            List<String> hostnames = extractUsingRegex(xmlContent, "<hostname>(.*?)</hostname>");
            List<String> ports = extractUsingRegex(xmlContent, "<port>(.*?)</port>");

            // 输出结果示例

            for (int i = 0; i < passwords.size(); i++) {
                byte[] decodedPassword = Base64.getDecoder().decode(passwords.get(i).getBytes());
                int payloadVersion = decodedPassword[0];

                if (payloadVersion == 1) {
                    System.out.println("# " + names.get(i) + "\n" + hostnames.get(i) + ":" + ports.get(i) + "\n" + usernames.get(i) + " / " + decryptNewPassword(secretPart, decodedPassword));
                } else {
                    System.out.println("# " + names.get(i) + "\n" + hostnames.get(i) + ":" + ports.get(i) + "\n" + usernames.get(i) + " / " + decryptOldPassword(secretPart, decodedPassword));
                }
            }

        } catch (Exception e) {
            e.printStackTrace();
        }

    }
    public static byte[] getHashedMasterKey(byte[] masterKey) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hashedMasterKey = digest.digest(masterKey);
        return Arrays.copyOf(hashedMasterKey, 16);
    }

    public static byte[] decryptAES(byte[] hashedMasterKey, byte[] hudsonSecretKey) throws Exception {
        SecretKeySpec secretKey = new SecretKeySpec(hashedMasterKey, "AES");
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);

        return cipher.doFinal(hudsonSecretKey);
    }

    public static List<String> extractUsingRegex(String content, String pattern) {
        List<String> matches = new ArrayList<>();
        Pattern regex = Pattern.compile(pattern, Pattern.DOTALL);
        Matcher matcher = regex.matcher(content);

        while (matcher.find()) {
            matches.add(matcher.group(1)); // Assuming you have only one capturing group in the regex pattern
        }
        return matches;
    }

    public static String decryptOldPassword(byte[] secret, byte[] p) {
        try {
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            SecretKeySpec secretKeySpec = new SecretKeySpec(secret, "AES");
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);

            byte[] decryptedData = cipher.doFinal(p);

            String decryptedString = new String(decryptedData, StandardCharsets.UTF_8);

            // Using the MAGIC sequence as byte array
            byte[] MAGIC = "::::MAGIC::::".getBytes(StandardCharsets.UTF_8);

            if (decryptedString.contains(new String(MAGIC, StandardCharsets.UTF_8))) {
                Pattern pattern = Pattern.compile("(.*)" + new String(MAGIC, StandardCharsets.UTF_8));
                Matcher matcher = pattern.matcher(decryptedString);

                if (matcher.find()) {
                    return matcher.group(1);
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return ""; // Return empty string if decryption fails or the magic string isn't found
    }

    public static String decryptNewPassword(byte[] secret, byte[] p) throws Exception {
        p = Arrays.copyOfRange(p, 1, p.length);
        int ivLength = ((p[0] & 0xff) << 24) | ((p[1] & 0xff) << 16) | ((p[2] & 0xff) << 8) | (p[3] & 0xff);
        p = Arrays.copyOfRange(p, 4, p.length);
        p = Arrays.copyOfRange(p, 4, p.length);
        byte[] iv = Arrays.copyOfRange(p, 0, ivLength);
        byte[] encryptedData = new byte[p.length - ivLength];
        System.arraycopy(p, 0, iv, 0, ivLength);
        System.arraycopy(p, ivLength, encryptedData, 0, p.length - ivLength);

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        SecretKeySpec secretKeySpec = new SecretKeySpec(secret, "AES");
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);
        byte[] decrypted = cipher.doFinal(encryptedData);

        byte[] fullyDecryptedBlocks;
        byte[] possiblyPaddedBlock;

        if (decrypted.length > 16) {
            fullyDecryptedBlocks = new byte[decrypted.length - 16];
            possiblyPaddedBlock = new byte[16];
            System.arraycopy(decrypted, 0, fullyDecryptedBlocks, 0, decrypted.length - 16);
            System.arraycopy(decrypted, decrypted.length - 16, possiblyPaddedBlock, 0, 16);
        } else {
            fullyDecryptedBlocks = new byte[0];
            possiblyPaddedBlock = decrypted;
        }
        int paddingLength;
        byte[] pwBytes;

        if (decrypted.length > 16) {
            paddingLength = decrypted[decrypted.length - 1] & 0xff;

            if (paddingLength <= 16) {
                System.arraycopy(decrypted, decrypted.length - 16, possiblyPaddedBlock, 0, 16 - paddingLength);
                pwBytes = new byte[decrypted.length - 16 + possiblyPaddedBlock.length];
                System.arraycopy(decrypted, 0, pwBytes, 0, decrypted.length - 16);
                System.arraycopy(possiblyPaddedBlock, 0, pwBytes, decrypted.length - 16, possiblyPaddedBlock.length);
            } else {
                pwBytes = decrypted;
            }
        } else {
            pwBytes = decrypted;
        }

        return new String(pwBytes, StandardCharsets.UTF_8);

    }


//    public static byte[] addPKCS5Padding(byte[] data) {
//        int blockSize = 16; // AES块大小为16字节
//        int paddingLength = blockSize - (data.length % blockSize);
//        byte paddingByte = (byte) paddingLength;
//
//        byte[] paddedData = Arrays.copyOf(data, data.length + paddingLength);
//        for (int i = data.length; i < paddedData.length; i++) {
//            paddedData[i] = paddingByte;
//        }
//
//        return paddedData;
//    }
//
//    public static byte[] removePKCS5Padding(byte[] paddedData) {
//        int paddingLength = paddedData[paddedData.length - 1] & 0xFF;
//        int unpaddedLength = paddedData.length - paddingLength;
//
//        return Arrays.copyOf(paddedData, unpaddedLength);
//    }
}
