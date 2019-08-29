package com.kaviraj.application.crypto;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;

import com.kaviraj.application.ApplicationConstants;
import com.kaviraj.application.exception.CryptoException;

@Component
public class AESEncryption {

	@Autowired
	private Environment environment;

	final static String CLASSNAME="Encryption.class";
	final static Logger LOGGER = LoggerFactory.getLogger(CLASSNAME);

	private static final String ERROR_IN_ENCRYPT_PASSWORD = "Exception while encrypting password";

	public String encrypt(String plainText) throws Exception {

		String encPass = environment.getProperty(ApplicationConstants.CRYPTO_PASSWORD,ApplicationConstants.CRYPTO_PROPERTIES);
		String initializationVector = environment.getProperty(ApplicationConstants.CRYPTO_INITIALIZATION_VECTOR,ApplicationConstants.CRYPTO_PROPERTIES);
		String salt = environment.getProperty(ApplicationConstants.CRYPTO_SALT,ApplicationConstants.CRYPTO_PROPERTIES);
		int pswdIterations = Integer.parseInt(environment.getProperty(ApplicationConstants.CRYPTO_PASSWORD_ITERATIONS,ApplicationConstants.CRYPTO_PROPERTIES));
		int keySize = Integer.parseInt(environment.getProperty(ApplicationConstants.CRYPTO__KEYSIZE,ApplicationConstants.CRYPTO_PROPERTIES));
		String secretKeyFactory = environment.getProperty(ApplicationConstants.CRYPTO_SECRET_KEY_FACTORY,ApplicationConstants.CRYPTO_PROPERTIES);
		String cValue = environment.getProperty(ApplicationConstants.CRYPTO_CVALUE,ApplicationConstants.CRYPTO_PROPERTIES);
		String type = environment.getProperty(ApplicationConstants.CRYPTO_TYPE,ApplicationConstants.CRYPTO_PROPERTIES);
		String format = environment.getProperty(ApplicationConstants.CRYPTO_FORMAT,ApplicationConstants.CRYPTO_PROPERTIES);

		byte[] saltBytes = salt.getBytes(format);
		byte[] ivBytes = initializationVector.getBytes(format);
		byte[] plainTextBytes = plainText.getBytes(format);

		SecretKeyFactory factory = SecretKeyFactory.getInstance(secretKeyFactory);
		PBEKeySpec spec = new PBEKeySpec(encPass.toCharArray(), saltBytes, pswdIterations, keySize);

		SecretKey secretKey = factory.generateSecret(spec);
		SecretKeySpec secret = new SecretKeySpec(secretKey.getEncoded(), type);

		Cipher cipher = Cipher.getInstance(cValue);
		cipher.init(Cipher.ENCRYPT_MODE, secret, new IvParameterSpec(ivBytes));

		byte[] encryptedTextBytes = null;
		try {
			encryptedTextBytes = cipher.doFinal(plainTextBytes);
		} catch (Exception e) {
			LOGGER.error("Exception while encrypting the text : "+plainText, e);
			throw new CryptoException(ERROR_IN_ENCRYPT_PASSWORD, e.getCause());
		}
		return new Base64().encodeAsString(encryptedTextBytes);
	}

}
