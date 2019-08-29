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
public class EncryptionDecryptionTest {

    @Autowired
    AESEncryption encryption;

    @Autowired
    AESDecryption decryption;

    @Test
    public void testEncryptionDecryption() {

        try {
            String originalValue = "WelcometoGDSM";

            String encryptedValue = encryption.encrypt(originalValue);

            assertNotNull(encryptedValue);

			String decryptedValue = decryption.decrypt(encryptedValue);  //IHPvcVgVWO5WxEkzJeiE9g==

            assertNotNull(decryptedValue);
            assertEquals(originalValue, decryptedValue);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
