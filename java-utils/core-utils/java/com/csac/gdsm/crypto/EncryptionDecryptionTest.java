package com.csac.gdsm.crypto;

import com.csac.gdsm.config.GDSMAppConfiguration;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import static org.junit.Assert.*;

@ContextConfiguration(classes = {GDSMAppConfiguration.class})
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

            //assertNotNull(encryptedValue);

			String decryptedValue = decryption.decrypt("U2FsdGVkX19lePJRn4xrhVH/bDXbLE6Dw00+YPCemLs=");  //IHPvcVgVWO5WxEkzJeiE9g==

            assertNotNull(decryptedValue);
            assertEquals(originalValue, decryptedValue);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
