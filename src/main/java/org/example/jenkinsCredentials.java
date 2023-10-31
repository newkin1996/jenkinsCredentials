import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.IvParameterSpec;
import java.io.FileInputStream;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class JenkinsCredentialsDecryptor {
    private static final String MAGIC = "::::MAGIC::::";
    private static final String SSH_XML_FILENAME = "jenkins.plugins.publish_over_ssh.BapSshPublisherPlugin.xml";

    public static void main(String[] args) {
        String jenkinsHome = System.getenv("JENKINS_HOME");
        if (jenkinsHome == null || jenkinsHome.isEmpty()) {
            System.err.println("JENKINS_HOME environment variable not set.");
            System.exit(1);
        }

        Path masterKeyPath = Paths.get(jenkinsHome, "secrets", "master.key");
        Path hudsonSecretKeyPath = Paths.get(jenkinsHome, "secrets", "hudson.util.Secret");

        if (args.length < 2 || !args[0].equals("-m")) {
            System.out.println("Usage: java JenkinsCredentialsDecryptor -m <mode>");
            System.exit(1);
        }

        String mode = args[1];

        if (mode.equals("ssh")) {
            Path xmlFilePath = Paths.get(jenkinsHome, SSH_XML_FILENAME);

            try {
                byte[] masterKey = Files.readAllBytes(masterKeyPath);
                System.out.println(masterKey.toString());
                byte[] hudsonSecretKey = Files.readAllBytes(hudsonSecretKeyPath);

                MessageDigest md = MessageDigest.getInstance("SHA-256");
                byte[] hashedMasterKey = md.digest(masterKey);
                byte[] encryptionKey = new byte[24];
                System.arraycopy(hashedMasterKey, 0, encryptionKey, 0, 16);
                System.arraycopy(hashedMasterKey, 0, encryptionKey, 16, 8);

                DESedeKeySpec keySpec = new DESedeKeySpec(encryptionKey);
                SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DESede");
                SecretKey secretKey = keyFactory.generateSecret(keySpec);

                Cipher cipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");
                byte[] iv = new byte[8];
                byte[] encodedSecret = Base64.getDecoder().decode(hudsonSecretKey);
                System.arraycopy(encodedSecret, 4, iv, 0, 8);
                IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
                cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec);

                String credentialsXml = new String(Files.readAllBytes(xmlFilePath));
                Pattern passwordPattern = Pattern.compile("<secretPassphrase>\\{(.+?)\\}</secretPassphrase>");
                Matcher passwordMatcher = passwordPattern.matcher(credentialsXml);

                while (passwordMatcher.find()) {
                    String encryptedPassword = passwordMatcher.group(1);
                    byte[] encryptedPasswordBytes = Base64.getDecoder().decode(encryptedPassword);

                    byte[] decryptedPasswordBytes = cipher.doFinal(encryptedPasswordBytes);
                    String decryptedPassword = new String(decryptedPasswordBytes, "UTF-8");

                    System.out.println(decryptedPassword);
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        } else {
            System.out.println("Unknown mode: " + mode);
            System.exit(1);
        }
    }
}
