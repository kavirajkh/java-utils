package com.kaviraj.application.crypto;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import com.kaviraj.application.config.AppConfiguration;
@ContextConfiguration(classes = {AppConfiguration.class})
@RunWith(SpringJUnit4ClassRunner.class)
public class AESCryptoUtilTest {

    @Autowired
    AESCryptoUtil cryptoUtil;
	
	@Test
	public void testEncrypt() {
		String passphrase = "Welcome1$";
		String cipherText = cryptoUtil.encrypt("613685164", passphrase);
		assertNotNull(cipherText);
	}

	@Test
	public void testDecrypt() {
		String passphrase = "Welcome1$";
		String message = "613685164";
		String cipherText = cryptoUtil.encrypt(message, passphrase);
		//String cipherText = "U2FsdGVkX19lePJRn4xrhVH/bDXbLE6Dw00+YPCemLs=";

		String decryptedMessage = cryptoUtil.decrypt(cipherText, passphrase);
		assertEquals(message, decryptedMessage);
	}

}
