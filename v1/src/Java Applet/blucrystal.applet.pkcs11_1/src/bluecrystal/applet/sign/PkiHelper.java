/*
    Blue Crystal: Document Digital Signature Tool
    Copyright (C) 2007-2015  Sergio Leal

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package bluecrystal.applet.sign;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.security.auth.x500.X500Principal;

public class PkiHelper {
	public static final int SHA1 = 0;
	public static final int SHA224 = 1;
	public static final int SHA256 = 2;
	public static final int SHA384 = 3;
	public static final int SHA512 = 4;
	public static String [] algName = {"SHA1withRSA", "SHA224withRSA", "SHA256withRSA", "SHA384withRSA", "SHA512withRSA"};

	public static byte[] calcSha1(byte[] src) {
		String hashType = "SHA1";
		return computeHash(src, hashType);
	}
	public static byte[] calcSha224(byte[] src) {
		String hashType = "SHA224";
		return computeHash(src, hashType);
	}
	public static byte[] calcSha256(byte[] src) {
		String hashType = "SHA256";
		return computeHash(src, hashType);
	}
	public static byte[] calcSha384(byte[] src) {
		String hashType = "SHA384";
		return computeHash(src, hashType);
	}
	public static byte[] calcSha512(byte[] src) {
		String hashType = "SHA512";
		return computeHash(src, hashType);
	}

	public static byte[] hashContent(int hashType, byte[] content) {
		byte[] ret = null;
		switch (hashType) {
		case PkiHelper.SHA1:
			ret = calcSha1(content);
			break;
		case PkiHelper.SHA224:
			ret = calcSha224(content);
			break;
		case PkiHelper.SHA256:
			ret = calcSha256(content);
			break;
		case PkiHelper.SHA384:
			ret = calcSha384(content);
			break;
		case PkiHelper.SHA512:
			ret = calcSha512(content);
			break;

		default:
			break;
		}

		return ret;
	}
	private static byte[] computeHash(byte[] src, String hashType) {
		byte[] result = null;
		try {
			MessageDigest digest = MessageDigest.getInstance(hashType);
			digest.update(src);

			result = digest.digest();
		} catch (NoSuchAlgorithmException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		return result;
	}

	public static String extractRDN(String rdn, X500Principal dn) {
		String cn = null;
		Matcher m = Pattern.compile("(" + rdn + "=[^,]+)")
				.matcher(dn.getName());
		if (m.find())
			cn = m.group(1);

		return cn == null ? "" : cn;

	}

	public static PrivateKey loadPrivFromP12(String certFilePath, String passwd)
			throws Exception {
		PrivateKey pk = null;
		java.security.KeyStore ks = java.security.KeyStore
				.getInstance("PKCS12");
		ks.load(new java.io.FileInputStream(certFilePath), passwd.toCharArray());
		// ks.load(new java.io.FileInputStream(certFilePath),null);

		Enumeration<String> aliases = ks.aliases();
		String nextAlias = "";
		while (aliases.hasMoreElements()) {
			nextAlias = aliases.nextElement();
			try {
				pk = (PrivateKey) ks.getKey(nextAlias, passwd.toCharArray());
				if (pk != null) {
					break;
				}
			} catch (UnrecoverableKeyException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();

			}
		}
		return pk;
	}

	public static byte[] sign(int alg, PrivateKey pk, byte[] data)
			throws Exception {
		Signature sig = Signature.getInstance(algName[alg]);
		sig.initSign(pk);
		sig.update(data);
		byte[] signatureBytes = sig.sign();
		
		return signatureBytes;
	}
	
	public static boolean verify(int alg, X509Certificate cert, byte[] data, byte[] sigToVerify)
			throws Exception {

		
		Signature sig = Signature.getInstance(algName[alg]);
		sig.initVerify(cert);
		sig.update(data);
		boolean verifies = sig.verify(sigToVerify);
		return verifies;
	}


	public static X509Certificate loadCertFromP12(String certFilePath, String passwd)
			throws KeyStoreException, IOException, NoSuchAlgorithmException,
			CertificateException, FileNotFoundException {
		X509Certificate x509 = null;
		java.security.KeyStore ks = java.security.KeyStore
				.getInstance("PKCS12");
		ks.load(new java.io.FileInputStream(certFilePath), passwd.toCharArray());
		// ks.load(new java.io.FileInputStream(certFilePath),null);

		Enumeration<String> aliases = ks.aliases();
		String nextAlias = "";
		while (aliases.hasMoreElements()) {
			try {
				nextAlias = aliases.nextElement();
				PrivateKey pk = (PrivateKey) ks.getKey(nextAlias, passwd.toCharArray());
				if (pk != null) {
					x509 = (X509Certificate) ks.getCertificate(nextAlias);
					break;
				}
			} catch (UnrecoverableKeyException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}

		}
		return x509;
	}	
}
