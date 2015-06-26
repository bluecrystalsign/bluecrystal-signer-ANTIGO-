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
		applet.init("aetpkss1.dll;eTPKCS11.dll;asepkcs.dll;libaetpkss.dylib;libeTPkcs11.dylib", "/usr/local/lib");
		applet.start();
	}

	@After
	public void tearDown() throws Exception {
	}

//	@Test
//	public void testListCerts() {
//		try {
//			
//			String ret = applet.listCerts(1, "qwerty");
//			System.out.println(ret);
//		} catch (Exception e) {
//			fail(e.getLocalizedMessage());
//		}
//	}
	
	@Test
	public void testSign() {
		try {
			
			String ret = applet.listCerts(0, "qwerty");
			System.out.println(ret);
			ret = applet.sign(0, 99, "qwerty", "FCB5BCA1564D6FC2",
					"UEsDBBQABgAIAAAAIQAcSWIw2wEAAD0NAAATAAgCW0NvbnRlbnRfVHlwZXNdLnhtbCCiBAIooAACAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADMl9tSgzAQhu+d8R2Y3DolrcfqlHrh4crTjPoAEbZtNCSZZFvt27tArUynFlvpyA1MCLv/tz8kLL3zj1QFE3BeGh2xTthmAejYJFIPI/b8dN3qssCj0IlQRkPEpuDZeX93p/c0teADitY+YiNEe8a5j0eQCh8aC5pmBsalAmnohtyK+E0Mge+328c8NhpBYwuzHKzfu4SBGCsMrj7ockFC4Sy4");
			System.out.println(ret);
		} catch (Exception e) {
			fail(e.getLocalizedMessage());
		}
	}

}
