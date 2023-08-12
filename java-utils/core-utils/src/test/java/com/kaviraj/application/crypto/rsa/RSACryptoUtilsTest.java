package com.kaviraj.application.crypto.rsa;

import java.io.FileInputStream;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import com.kaviraj.application.config.AppConfiguration;

@ContextConfiguration(classes = { AppConfiguration.class })
@RunWith(SpringJUnit4ClassRunner.class)
public class RSACryptoUtilsTest {

	@Autowired
	RSACryptoUtils cryptoUtil;

	@Test
	public void testGenerateKeyPair() throws Exception {
		KeyPair keyPair = cryptoUtil.generateKeyPair();
		Assert.assertNotNull(keyPair);
	}

	@Test
	public void testGetKeyPairFromKeyStore() throws Exception {
		KeyPair keyPair = cryptoUtil.getKeyPairFromKeyStore();
		Assert.assertNotNull(keyPair);
	}

	@Test
	public void testEncrypt() throws Exception {
		// secret message
		String message = "the answer to life the universe and everything";

		KeyPair keyPair = cryptoUtil.getKeyPairFromKeyStore();
		// Encrypt the message
		String cipherText = cryptoUtil.encrypt(message, keyPair.getPublic());
		Assert.assertNotNull(cipherText);
	}

	@Test
	public void testDecrypt() throws Exception {
		// secret message
		String message = "the answer to life the universe and everything";

		KeyPair keyPair = cryptoUtil.getKeyPairFromKeyStore();
		// Encrypt the message
		String cipherText = cryptoUtil.encrypt(message, keyPair.getPublic());
		// Now decrypt it
		String decipheredMessage = cryptoUtil.decrypt(cipherText, keyPair.getPrivate());
		Assert.assertEquals(message, decipheredMessage);
	}
	
	/*
	 * @Test public void testDecrypt_1() throws Exception { // secret message String
	 * message = "the answer to life the universe and everything";
	 * 
	 * FileInputStream fis_private = new
	 * FileInputStream("src/main/resources/crypto/privateKey"); FileInputStream
	 * fis_public = new FileInputStream("src/main/resources/crypto/publicKey");
	 * 
	 * KeyFactory kf = KeyFactory.getInstance("RSA"); PrivateKey privateKey =
	 * kf.generatePrivate(new PKCS8EncodedKeySpec(fis_private.readAllBytes()));
	 * PublicKey publicKey = kf.generatePublic(new
	 * X509EncodedKeySpec(fis_public.readAllBytes()));
	 * 
	 * KeyPair keyPair = cryptoUtil.getKeyPairFromKeyStore(); // Encrypt the message
	 * String cipherText = cryptoUtil.encrypt(message, publicKey); // Now decrypt it
	 * String decipheredMessage = cryptoUtil.decrypt(cipherText, privateKey);
	 * Assert.assertEquals(message, decipheredMessage); }
	 */
	
	@Test
	public void testDecrypt1() throws Exception {
		// secret message
		String message = "the answer to life the universe and everything";
		
		KeyPair keyPair = cryptoUtil.getKeyPairFromKeyStore();
		// Encrypt the message
		String cipherText = cryptoUtil.encrypt(message, keyPair.getPublic());
		// Now decrypt it
		String decipheredMessage = cryptoUtil.decrypt(cipherText, keyPair.getPrivate());
		Assert.assertEquals(message, decipheredMessage);
	}

	@Test
	public void testSign() throws Exception {
		KeyPair keyPair = cryptoUtil.getKeyPairFromKeyStore();
		// Let's sign our message
		String signature = cryptoUtil.sign("foobar", keyPair.getPrivate());
		Assert.assertNotNull(signature);
	}

	@Test
	public void testVerify() throws Exception {
		KeyPair keyPair = cryptoUtil.getKeyPairFromKeyStore();
		// Let's sign our message
		String signature = cryptoUtil.sign("foobar", keyPair.getPrivate());
		// Let's check the signature
		boolean isCorrect = cryptoUtil.verify("foobar", signature, keyPair.getPublic());
		Assert.assertTrue(isCorrect);
	}

}
