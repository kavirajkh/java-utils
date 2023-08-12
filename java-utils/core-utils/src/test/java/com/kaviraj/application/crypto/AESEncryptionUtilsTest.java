package com.kaviraj.application.crypto;

import static org.junit.Assert.*;

import java.util.Base64;

import javax.crypto.spec.IvParameterSpec;

import org.junit.Test;

public class AESEncryptionUtilsTest {

	//@Test
	public void testCreateAESKEY() {
		fail("Not yet implemented");
	}

	//@Test
	public void testCreateAESKEYWithSalt() {
		fail("Not yet implemented");
	}

	//@Test
	public void testAESEnc() {
		String key = AESEncryptionUtils.createAESKEYWithSalt();
	      IvParameterSpec ivParameterSpec = AESEncryptionUtils.generateIv();
	      System.out.println("Key: "+key);

	      String text= "Good Luck UDP";
	      ivParameterSpec = new IvParameterSpec("bYHPF2w5G8L6JOrX".getBytes());
	      String value=AESEncryptionUtils.AESEnc(key,text,ivParameterSpec);
	      byte[] base64Encoded = Base64.getEncoder().encode(ivParameterSpec.getIV());
	      String ivString = new String(base64Encoded);
	      System.out.println("IV："+ivString);
	      System.out.println("AES Encrypted string："+value);
	}

	//@Test
	public void testAESDec() {
		//Key: J1KL8D6BS5oq8qlqk6/K0UZh+agkFOKeEWWehegzkgM=
		//IV：YllIUEYydzVHOEw2Sk9yWA==
		//AES Encrypted string：bGIoZype+AFbWk0lZq1GKw==
		
		String key = "J1KL8D6BS5oq8qlqk6/K0UZh+agkFOKeEWWehegzkgM=";
		System.out.println("Secret Key: " + key);
		String text = "bGIoZype+AFbWk0lZq1GKw==";
		 byte[] decodedIV = AESEncryptionUtils.base64Dec("YllIUEYydzVHOEw2Sk9yWA==");
		String value = AESEncryptionUtils.AESDec(key, text, decodedIV);
		System.out.println("AES Decrypted string：" + value);
	}
	
	@Test
	public void testAESEncWK() {


	      String text= "Good Luck UDP";
	      String value=AESEncryptionUtils.AESEnc(text);
	      System.out.println("AES Encrypted string："+value);
	}

	@Test
	public void testAESDecWK() {
		String text = "bGIoZype+AFbWk0lZq1GKw==";
		String value = AESEncryptionUtils.AESDec(text);
		System.out.println("AES Decrypted string：" + value);
	}

}
