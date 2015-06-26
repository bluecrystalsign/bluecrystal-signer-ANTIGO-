package com.ittru.applet.sign.test;

import static org.junit.Assert.fail;

import java.io.FileInputStream;
import java.security.KeyStore;
import java.util.Enumeration;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import bluecrystal.applet.sign.FileChooser;
import bluecrystal.applet.sign.Pkcs11;

public class Pkcs11Test {

	@Before
	public void setUp() throws Exception {
	}

	@After
	public void tearDown() throws Exception {
	}

	@Test
	public void testLoadKeyStoreMscapi() {
		fail("Not yet implemented");
	}

//	@Test
//	public void testLoadKeyStorep11() {
//		try {
//			Pkcs11 p11 = new Pkcs11("aetpkss1.dll;eTPKCS11.dll", "");
//			p11.loadKeyStorep11();
//			KeyStore keyStore = p11.getKeyStore();
//			Enumeration aliasesEnum = keyStore.aliases();
//			while (aliasesEnum.hasMoreElements()) {
//				System.out.println((String) aliasesEnum.nextElement());
//				
//			}
//		} catch (Exception e) {
//			e.printStackTrace();
//			fail(e.getLocalizedMessage());
//		}
//	}
	
	@Test
	public void testLoadKeyStoreMsCapi() {
		try {
//			Pkcs11 p11 = new Pkcs11("aetpkss1.dll;eTPKCS11.dll");
//			p11.loadKeyStoreMscapi();
//			KeyStore keyStore = p11.getKeyStore();
//			Enumeration aliasesEnum = keyStore.aliases();
//			while (aliasesEnum.hasMoreElements()) {
//				System.out.println((String) aliasesEnum.nextElement());
//				
//			}
			
			System.out.println("loadKeyStoreMscapi");
			KeyStore capiStore = KeyStore.getInstance("Windows-MY");
			capiStore.load(null, null);
			Enumeration<String> aliases = capiStore.aliases();
			System.out.println("loadKeyStoreMscapi");
			while (aliases.hasMoreElements()) {
				System.out.println(aliases.nextElement());
			}

			
		} catch (Exception e) {
			e.printStackTrace();
			fail(e.getLocalizedMessage());
		}
	}
	
	
	@Test
	public void testLoadKeyStoreP12() {
		try {
			System.out.println("testLoadKeyStoreP12");
			KeyStore capiStore = KeyStore.getInstance("pkcs12", "SunJSSE");
			capiStore.load(new FileInputStream("C:\\Users\\sergio\\Dropbox\\Produtos\\deploy\\certs\\apt2.p12"), "qwerty".toCharArray());
			Enumeration<String> aliases = capiStore.aliases();
			System.out.println("loadKeyStoreMscapi");
			while (aliases.hasMoreElements()) {
				System.out.println(aliases.nextElement());
			}

			
		} catch (Exception e) {
			e.printStackTrace();
			fail(e.getLocalizedMessage());
		}
	}
	
	

}
