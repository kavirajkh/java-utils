package com.kaviraj.application.crypto;

import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.lang3.StringUtils;

public class AESEncryptionUtils {

	private static final String AES = "AES";
	private static final String AES_TRANSFORMATION = "AES/CBC/PKCS5Padding";
	private static final String AES_ALGORITHM = "PBKDF2WithHmacSHA256";

	private static final String SECRET = "MnOXJSwFm4Y4Fa2052exaOexOwhH6CCOsyQtBHRes";
	private static final String SALT = "Xacua";
	private static final String DEFAULT_KEY = "J1KL8D6BS5oq8qlqk6/K0UZh+agkFOKeEWWehegzkgM=";
	private static final String DEFAULT_IV = "bYHPF2w5G8L6JOrX";

	public static String createAESKEY() {
		try {

			KeyGenerator keyGenerator = KeyGenerator.getInstance(AES);
			keyGenerator.init(256, new SecureRandom());
			SecretKey secretKey = keyGenerator.generateKey();
			return base64Enc(secretKey.getEncoded());
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		return null;
	}

	public static String createAESKEYWithSalt() {
		try {

			SecretKeyFactory factory = SecretKeyFactory.getInstance(AES_ALGORITHM);
			KeySpec spec = new PBEKeySpec(SECRET.toCharArray(), SALT.getBytes(), 65536, 256);
			SecretKey tmp = factory.generateSecret(spec);
			SecretKeySpec secretKey = new SecretKeySpec(tmp.getEncoded(), AES);
			return base64Enc(secretKey.getEncoded());
		} catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
			e.printStackTrace();
		}
		return StringUtils.EMPTY;
	}

	public static String AESEnc(String key, String msg, IvParameterSpec iv) {
		SecretKeySpec keySpec = new SecretKeySpec(base64Dec(key), AES);
		try {
			Cipher cipher = Cipher.getInstance(AES_TRANSFORMATION);
			cipher.init(Cipher.ENCRYPT_MODE, keySpec, iv);
			return base64Enc(cipher.doFinal(msg.getBytes()));
		} catch (Exception e) {
			e.printStackTrace();
		}
		return StringUtils.EMPTY;
	}

	public static String AESDec(String key, String msg, byte[] base64DecodedIV) {
		SecretKeySpec keySpec = new SecretKeySpec(base64Dec(key), AES);
		try {
			Cipher cipher = Cipher.getInstance(AES_TRANSFORMATION);
			cipher.init(Cipher.DECRYPT_MODE, keySpec, new IvParameterSpec(base64DecodedIV));
			byte[] cipherRespFinal = cipher.doFinal(base64Dec(msg));
			return new String(cipherRespFinal, StandardCharsets.UTF_8.name());
		} catch (Exception e) {
			e.printStackTrace();
		}
		return StringUtils.EMPTY;
	}

	public static String AESEnc(String msg) {

		if (msg != null) {

			SecretKeySpec keySpec = new SecretKeySpec(base64Dec(DEFAULT_KEY), AES);
			try {
				Cipher cipher = Cipher.getInstance(AES_TRANSFORMATION);

				IvParameterSpec ivParameterSpec = AESEncryptionUtils.generateIv();

				ivParameterSpec = new IvParameterSpec(DEFAULT_IV.getBytes());

				cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivParameterSpec);
				return base64Enc(cipher.doFinal(msg.getBytes()));
			} catch (Exception e) {
				e.printStackTrace();
			}
		}

		return StringUtils.EMPTY;
	}

	public static String AESDec(String msg) {

		if (msg != null) {

			SecretKeySpec keySpec = new SecretKeySpec(base64Dec(DEFAULT_KEY), AES);
			try {
				Cipher cipher = Cipher.getInstance(AES_TRANSFORMATION);
				cipher.init(Cipher.DECRYPT_MODE, keySpec, new IvParameterSpec(DEFAULT_IV.getBytes()));
				byte[] cipherRespFinal = cipher.doFinal(base64Dec(msg));
				return new String(cipherRespFinal, StandardCharsets.UTF_8.name());
			} catch (Exception e) {
				e.printStackTrace();
			}
		}

		return StringUtils.EMPTY;
	}

	public static String base64Enc(byte[] msg) {
		return Base64.getEncoder().encodeToString(msg);
	}

	public static byte[] base64Dec(String msg) {
		return Base64.getDecoder().decode(msg);
	}

	public static IvParameterSpec generateIv() {
		byte[] iv = new byte[16];
		new SecureRandom().nextBytes(iv);
		// iv = RandomStringUtils.randomAlphanumeric(16).getBytes();

		return new IvParameterSpec(iv);
	}
	
	
	
	

}