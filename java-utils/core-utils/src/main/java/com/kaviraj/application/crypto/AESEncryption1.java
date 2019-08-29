package com.kaviraj.application.crypto;

import java.nio.charset.StandardCharsets;
import java.security.DigestException;
import java.security.Key;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class AESEncryption1 {

	private static final String ALGO = "AES";
	private byte[] key;

	public AESEncryption1(String key) {
			this.key = key.getBytes();
		}

	private String encryptUtil(String valueToEncrypt) throws Exception {
		Key secretkey = generateKey();
		System.out.println("Algorithm " + secretkey.getAlgorithm());
		Cipher cipher = Cipher.getInstance(ALGO);
		cipher.init(Cipher.ENCRYPT_MODE, secretkey);
		byte[] encValue = cipher.doFinal(valueToEncrypt.getBytes());
		String encryptedValue = Base64.getEncoder().encodeToString(encValue);
		return encryptedValue;

	}

	private String decryptUtil(String valueToDecrypt) throws Exception {
		Key secretkey = generateKey();
		Cipher cipher = Cipher.getInstance(ALGO);
		cipher.init(Cipher.DECRYPT_MODE, secretkey);
		byte[] decode = Base64.getDecoder().decode(valueToDecrypt);
		byte[] decryptedByteArray = cipher.doFinal(decode);
		String decryptedValue = new String(decryptedByteArray);
		return decryptedValue;

	}

	private Key generateKey() {
		Key secretKeySpec = new SecretKeySpec(key, ALGO);
		return secretKeySpec;

	}

	public static void main(String[] args) throws Exception {

		/*
		 * AESEncryption1 aesEncryption = new
		 * AESEncryption1("abcdfertyhng1235abcdfertyhng1235"); String encryptedString =
		 * aesEncryption.encryptUtil("613685164"); System.out.println("encryptedString "
		 * + encryptedString); // AESEncryption aesEncryption1 = new
		 * AESEncryption("123wertgfdscvbnh"); String decryptedString =
		 * aesEncryption.decryptUtil(encryptedString);
		 * System.out.println("decryptedString " + decryptedString);
		 */
		
		String secret = "Welcome1$";
		String cipherText = "U2FsdGVkX19lePJRn4xrhVH/bDXbLE6Dw00+YPCemLs=";
		MessageDigest md5 = MessageDigest.getInstance("MD5");
		Cipher aesCBCEnc = Cipher.getInstance("AES/CBC/PKCS5Padding");
		
		byte[] saltDataEnc = "qwertyui".getBytes();
		final byte[][] keyAndIVEnc = GenerateKeyAndIV(32, 16, 1, saltDataEnc, secret.getBytes(StandardCharsets.UTF_8), md5);
		
		SecretKeySpec keyEnc = new SecretKeySpec(keyAndIVEnc[0], "AES");
		IvParameterSpec ivEnc = new IvParameterSpec(keyAndIVEnc[1]);
		aesCBCEnc.init(Cipher.ENCRYPT_MODE, keyEnc, ivEnc);
		byte[] encValue = aesCBCEnc.doFinal("613685164".getBytes());
		
		String encryptedValue = Base64.getEncoder().encodeToString(encValue);


		byte[] cipherData = Base64.getDecoder().decode(encryptedValue);
		byte[] saltData = Arrays.copyOfRange(cipherData, 8, 16);

		final byte[][] keyAndIV = GenerateKeyAndIV(32, 16, 1, saltData, secret.getBytes(StandardCharsets.UTF_8), md5);
		SecretKeySpec key = new SecretKeySpec(keyAndIV[0], "AES");
		IvParameterSpec iv = new IvParameterSpec(keyAndIV[1]);

		byte[] encrypted = Arrays.copyOfRange(cipherData, 16, cipherData.length);
		Cipher aesCBC = Cipher.getInstance("AES/CBC/PKCS5Padding");
		aesCBC.init(Cipher.DECRYPT_MODE, key, iv);
		byte[] decryptedData = aesCBC.doFinal(encrypted);
		String decryptedText = new String(decryptedData, StandardCharsets.UTF_8);

		System.out.println(decryptedText);
	}
	
	
	public static byte[][] GenerateKeyAndIV(int keyLength, int ivLength, int iterations, byte[] salt, byte[] password, MessageDigest md) {

	    int digestLength = md.getDigestLength();
	    int requiredLength = (keyLength + ivLength + digestLength - 1) / digestLength * digestLength;
	    byte[] generatedData = new byte[requiredLength];
	    int generatedLength = 0;

	    try {
	        md.reset();

	        // Repeat process until sufficient data has been generated
	        while (generatedLength < keyLength + ivLength) {

	            // Digest data (last digest if available, password data, salt if available)
	            if (generatedLength > 0)
	                md.update(generatedData, generatedLength - digestLength, digestLength);
	            md.update(password);
	            if (salt != null)
	                md.update(salt, 0, 8);
	            md.digest(generatedData, generatedLength, digestLength);

	            // additional rounds
	            for (int i = 1; i < iterations; i++) {
	                md.update(generatedData, generatedLength, digestLength);
	                md.digest(generatedData, generatedLength, digestLength);
	            }

	            generatedLength += digestLength;
	        }

	        // Copy key and IV into separate byte arrays
	        byte[][] result = new byte[2][];
	        result[0] = Arrays.copyOfRange(generatedData, 0, keyLength);
	        if (ivLength > 0)
	            result[1] = Arrays.copyOfRange(generatedData, keyLength, keyLength + ivLength);

	        return result;

	    } catch (DigestException e) {
	        throw new RuntimeException(e);

	    } finally {
	        // Clean out temporary data
	        Arrays.fill(generatedData, (byte)0);
	    }
	}
}
