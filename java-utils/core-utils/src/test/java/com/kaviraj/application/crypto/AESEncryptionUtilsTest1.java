package com.kaviraj.application.crypto;

import java.util.Base64;

import javax.crypto.spec.IvParameterSpec;

import org.junit.Test;

public class AESEncryptionUtilsTest1 {

	@Test
    public void testAESEnc() {
      String key = AESEncryptionUtils.createAESKEYWithSalt();
      IvParameterSpec ivParameterSpec = AESEncryptionUtils.generateIv();
      System.out.println("Key: "+key);

      String text="{\"ssn\": [\"606066960\",\"877600250\"],\"academicYr\": \"2021\",\"schoolCode\": \"00115000\"}";
     // String text= "Good Luck";
      ivParameterSpec = new IvParameterSpec("bYHPF2w5G8L6JOrX".getBytes());
      String value=AESEncryptionUtils.AESEnc(key,text,ivParameterSpec);
      byte[] base64Encoded = Base64.getEncoder().encode(ivParameterSpec.getIV());
      String ivString = new String(base64Encoded);
      System.out.println("IV："+ivString);
      System.out.println("AES Encrypted string："+value);
      testAESDec(key,ivString,value);
    }

	@Test
	public void testAESDec(String key,String ivString,String msg) {
        System.out.println("Key: " + key);
        byte[] decodedIV = Base64.getDecoder().decode(ivString);
        String value = AESEncryptionUtils.AESDec(key,msg,decodedIV);
        System.out.println("AES Decrypted string：" + value);
    }
	
	@Test
	public void testAESDecWithSecretKEY() {

		String key = AESEncryptionUtils.createAESKEYWithSalt();
		System.out.println("Secret Key: " + key);
		String text = "ONCww4Ss9L3E8Q0DvQK6cFWX6QkytB2RWq9/Yeb+oQf3I1mHeztik68sBL6t/FRE8isSGB2lgo0Qu3esWr3sZPQLUVi4UGvFnojp78NzmhnEhb2SFR4MqEmD+/WoqjMHsasshWVUd5Chn7J0inxUviSuXNBnhS1yygq3V5m6+AUt93OExyeqr5ZFmVdwsVSuUNJMyIsd3kacCCvkE+DazSTQNpCiw40D0EqL7yOa9qD2x+bIbBfU6qD3L032m1PcwAO05ps9f6fD9AYH1r1mTa4foefdRXW6YltguJxAauZTRwTL8rfLLuruVxu3VpGTW4xiHXSuYByLu7Iw2liiW3MAWYu34sGHUlwYxTpT52DL1oacUV8dL5xFoWzX5XDF4LKGBItncJ2vYmFdJu4NCcqpwtbmV1K0kes1kvhfwejqb5Nnfa26fy3t1sVhLsIUgSTYQ+B7Skr0MO468g99L5MRGaerAZrb7E7B72HVPiFGkkP85fm67rZIlgkSJsnMse5Dt3oORa2PEv9ZNeupTJjME9nV+hFXAamyN6fCx8TjMJNS+dPa9iOv+/0GLypJ9HcyL4/BUyRi0ujwTobsWil8n9S2elIOTsZJkHeOgJBM6cRgl9b6E9E3Gceht0M/O+9GYe86n0AgeHyOUJEd3rRVxVWNy7LOzRwr8GpxoPH9AKgRQuNVD2gLhLZz3y+xHHoKIllIik0Q7w2ZqISS0fSmm3XhtIBIeIqGQlRfR0CPcsk7ErGCJEahJWRWPvoB1TNPryUAdfpxLETLvXzV3EZLTUXl1l2++dciP6Kzp4s=";
		 byte[] decodedIV = AESEncryptionUtils.generateIv().getIV();
		 decodedIV = AESEncryptionUtils.base64Dec("hTEw297tvxhiNOw42Wp0zA==");
		String value = AESEncryptionUtils.AESDec(key, text, decodedIV);
		System.out.println("AES Decrypted string：" + value);
	}

}
