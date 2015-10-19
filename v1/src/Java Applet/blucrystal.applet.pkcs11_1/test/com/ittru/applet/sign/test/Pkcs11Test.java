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
			KeyStore keyStore = KeyStore.getInstance("pkcs12", "SunJSSE");
			keyStore.load(new FileInputStream("C:\\Users\\sergio.fonseca\\iniciativas\\bluecrystal\\content\\gmail_comodo.pfx"), "qwerty".toCharArray());
			Enumeration<String> aliases = keyStore.aliases();
			while (aliases.hasMoreElements()) {
				System.out.println(aliases.nextElement());
			}

			
		} catch (Exception e) {
			e.printStackTrace();
			fail(e.getLocalizedMessage());
		}
	}
	
	@Test
	public void testSignFileP12Sha256() {
		try {
			Pkcs11 p11 = new Pkcs11("aetpkss1.dll;eTPKCS11.dll", "");
			p11.setLastFilePath("C:\\Users\\sergio.fonseca\\iniciativas\\bluecrystal\\content\\gmail_comodo.pfx");
			p11.setStore(1);
			p11.setUserPIN("qwerty");
			p11.setAlg(2);
			p11.setOrig("MYIB8zAcBgkqhkiG9w0BCQUxDxcNMTUxMDE5MTYxNDQyWjCBlAYLKoZIhvcNAQkQAg8xgYQwgYEGCGBMAQcBAQIBMC8wCwYJYIZIAWUDBAIBBCDdV8mKQxO8E5jOZUPTgCRYlXz3Fq4ylOxNjCYlEpHmwTBEMEIGCyqGSIb3DQEJEAUBFjNodHRwOi8vcG9saXRpY2FzLmljcGJyYXNpbC5nb3YuYnIvUEFfQURfUkJfdjJfMS5kZXIwgfAGCyqGSIb3DQEJEAIvMYHgMIHdMIHaMIHXBCDw7BO5BkNhP1aqForUx0hz8/W+RIMIZ1oCEEkB7g6NRDCBsjCBnaSBmjCBlzELMAkGA1UEBhMCR0IxGzAZBgNVBAgTEkdyZWF0ZXIgTWFuY2hlc3RlcjEQMA4GA1UEBxMHU2FsZm9yZDEaMBgGA1UEChMRQ09NT0RPIENBIExpbWl0ZWQxPTA7BgNVBAMTNENPTU9ETyBSU0EgQ2xpZW50IEF1dGhlbnRpY2F0aW9uIGFuZCBTZWN1cmUgRW1haWwgQ0ECEBb+U7BVq86Tju5L8K/4UVYwLwYJKoZIhvcNAQkEMSIEIJ9oRV/uRGeigVcY+48UWqW6Foco8JfdjeJfvKjkzBOmMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0BBwE=");
			p11.sign();
		} catch (Exception e) {
			fail(e.getLocalizedMessage());
		}
	}
	

}
