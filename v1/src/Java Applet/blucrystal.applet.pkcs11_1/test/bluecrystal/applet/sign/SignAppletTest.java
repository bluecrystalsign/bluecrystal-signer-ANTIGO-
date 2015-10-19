package bluecrystal.applet.sign;

import static org.junit.Assert.*;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

public class SignAppletTest {
	SignApplet applet;

	@Before
	public void setUp() throws Exception {
		applet = new SignApplet();
		applet.init(
				"aetpkss1.dll;eTPKCS11.dll;asepkcs.dll;libaetpkss.dylib;libeTPkcs11.dylib",
				"/usr/local/lib");
		applet.start();
	}

	@After
	public void tearDown() throws Exception {
	}

	// @Test
	// public void testListCerts() {
	// try {
	//
	// String ret = applet.listCerts(1, "qwerty");
	// System.out.println(ret);
	// } catch (Exception e) {
	// fail(e.getLocalizedMessage());
	// }
	// }

	@Test
	public void testSignDevice() {
		try {

			String ret = applet.listCerts(0, "qwerty");
			System.out.println(ret);
			ret = applet
					.sign(0,
							99,
							"qwerty",
							"FCB5BCA1564D6FC2",
							"UEsDBBQABgAIAAAAIQAcSWIw2wEAAD0NAAATAAgCW0NvbnRlbnRfVHlwZXNdLnhtbCCiBAIooAACAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADMl9tSgzAQhu+d8R2Y3DolrcfqlHrh4crTjPoAEbZtNCSZZFvt27tArUynFlvpyA1MCLv/tz8kLL3zj1QFE3BeGh2xTthmAejYJFIPI/b8dN3qssCj0IlQRkPEpuDZeX93p/c0teADitY+YiNEe8a5j0eQCh8aC5pmBsalAmnohtyK+E0Mge+328c8NhpBYwuzHKzfu4SBGCsMrj7ockFC4Sy4");
			System.out.println(ret);
		} catch (Exception e) {
			fail(e.getLocalizedMessage());
		}
	}

//	@Test
//	public void testSignFileP12Sha256() {
//		try {
//			if (applet.isActive()) {
//				String ret = applet.listCerts(1, "qwerty");
//
//				// String ret = applet.listCerts(1, "qwerty");
//				// System.out.println(ret);
//				ret = applet.sign(1,
//								2,
//								"qwerty",
//								"id comodo ca limited da/do",
//								"MYIB8zAcBgkqhkiG9w0BCQUxDxcNMTUxMDE5MTYxNDQyWjCBlAYLKoZIhvcNAQkQAg8xgYQwgYEGCGBMAQcBAQIBMC8wCwYJYIZIAWUDBAIBBCDdV8mKQxO8E5jOZUPTgCRYlXz3Fq4ylOxNjCYlEpHmwTBEMEIGCyqGSIb3DQEJEAUBFjNodHRwOi8vcG9saXRpY2FzLmljcGJyYXNpbC5nb3YuYnIvUEFfQURfUkJfdjJfMS5kZXIwgfAGCyqGSIb3DQEJEAIvMYHgMIHdMIHaMIHXBCDw7BO5BkNhP1aqForUx0hz8/W+RIMIZ1oCEEkB7g6NRDCBsjCBnaSBmjCBlzELMAkGA1UEBhMCR0IxGzAZBgNVBAgTEkdyZWF0ZXIgTWFuY2hlc3RlcjEQMA4GA1UEBxMHU2FsZm9yZDEaMBgGA1UEChMRQ09NT0RPIENBIExpbWl0ZWQxPTA7BgNVBAMTNENPTU9ETyBSU0EgQ2xpZW50IEF1dGhlbnRpY2F0aW9uIGFuZCBTZWN1cmUgRW1haWwgQ0ECEBb+U7BVq86Tju5L8K/4UVYwLwYJKoZIhvcNAQkEMSIEIJ9oRV/uRGeigVcY+48UWqW6Foco8JfdjeJfvKjkzBOmMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0BBwE=");
//				System.out.println(ret);
//			} else {
//				System.out.println("Applet não está ativa!");
//			}
//		} catch (Exception e) {
//			fail(e.getLocalizedMessage());
//		}
//	}

	// *** sign ***
	// userPIN: qwerty
	// certAlias: id comodo ca limited da/do
	// orig:
	// MYIB8zAcBgkqhkiG9w0BCQUxDxcNMTUxMDE5MTYxNDQyWjCBlAYLKoZIhvcNAQkQAg8xgYQwgYEGCGBMAQcBAQIBMC8wCwYJYIZIAWUDBAIBBCDdV8mKQxO8E5jOZUPTgCRYlXz3Fq4ylOxNjCYlEpHmwTBEMEIGCyqGSIb3DQEJEAUBFjNodHRwOi8vcG9saXRpY2FzLmljcGJyYXNpbC5nb3YuYnIvUEFfQURfUkJfdjJfMS5kZXIwgfAGCyqGSIb3DQEJEAIvMYHgMIHdMIHaMIHXBCDw7BO5BkNhP1aqForUx0hz8/W+RIMIZ1oCEEkB7g6NRDCBsjCBnaSBmjCBlzELMAkGA1UEBhMCR0IxGzAZBgNVBAgTEkdyZWF0ZXIgTWFuY2hlc3RlcjEQMA4GA1UEBxMHU2FsZm9yZDEaMBgGA1UEChMRQ09NT0RPIENBIExpbWl0ZWQxPTA7BgNVBAMTNENPTU9ETyBSU0EgQ2xpZW50IEF1dGhlbnRpY2F0aW9uIGFuZCBTZWN1cmUgRW1haWwgQ0ECEBb+U7BVq86Tju5L8K/4UVYwLwYJKoZIhvcNAQkEMSIEIJ9oRV/uRGeigVcY+48UWqW6Foco8JfdjeJfvKjkzBOmMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0BBwE=
	// alg: 2
	// store: 1

}
