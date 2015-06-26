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

package bluecrystal.bcdeps.helper;

import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Enumeration;
import java.util.Iterator;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerId;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.util.Store;

import bluecrystal.domain.helper.IttruLoggerFactory;

public class PkiOps {

	private static final String SHA1WITH_RSA = "SHA1withRSA";
	private static final String SHA224WITH_RSA = "SHA224withRSA";
	private static final String SHA256WITH_RSA = "SHA256withRSA";
	private static final String SHA384WITH_RSA = "SHA384withRSA";
	private static final String SHA512WITH_RSA = "SHA512withRSA";
	private static final long MAXLENGTH = 100 * 1024 * 1024;
	
	static {
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
	}

	public PkiOps() {
		super();
	}

	public boolean verify(String contentPath, String envPath) throws Exception {

		CMSSignedData csd = null;
		byte[] buffer = loadEnv(envPath);
		if (contentPath != null) {
			byte[] content = getBytesFromFile(new File(contentPath));
			CMSProcessableByteArray cpbfile = new CMSProcessableByteArray(
					content);
			csd = new CMSSignedData(cpbfile, buffer);
		} else {
			csd = new CMSSignedData(buffer);
		}

		return verify(csd);

	}
	
	

	public static byte[] signSha1(PrivateKey pk, byte[] data) throws Exception {
		String alg = SHA1WITH_RSA;
		return signByAlg(pk, data, alg);
	}

	public static byte[] signSha224(PrivateKey pk, byte[] data)
			throws Exception {
		String alg = SHA224WITH_RSA;
		return signByAlg(pk, data, alg);
	}

	public static byte[] signSha256(PrivateKey pk, byte[] data)
			throws Exception {
		String alg = SHA256WITH_RSA;
		return signByAlg(pk, data, alg);
	}

	public static byte[] signSha384(PrivateKey pk, byte[] data)
			throws Exception {
		String alg = SHA384WITH_RSA;
		return signByAlg(pk, data, alg);
	}

	public static byte[] signSha512(PrivateKey pk, byte[] data)
			throws Exception {
		String alg = SHA512WITH_RSA;
		return signByAlg(pk, data, alg);
	}

	private static byte[] signByAlg(PrivateKey pk, byte[] data, String alg)
			throws NoSuchAlgorithmException, InvalidKeyException,
			SignatureException {
		Signature sig = Signature.getInstance(alg);
		sig.initSign(pk);
		sig.update(data);
		byte[] signatureBytes = sig.sign();
		return signatureBytes;
	}

	public byte[] calcSha1(byte[] content) throws NoSuchAlgorithmException {
		String algorithm = "SHA1";
		return calcSha(content, algorithm);
	}

	public byte[] calcSha224(byte[] content) throws NoSuchAlgorithmException {
		String algorithm = "SHA224";
		return calcSha(content, algorithm);
	}

	public byte[] calcSha256(byte[] content) throws NoSuchAlgorithmException {
		String algorithm = "SHA256";
		return calcSha(content, algorithm);
	}

	public byte[] calcSha384(byte[] content) throws NoSuchAlgorithmException {
		String algorithm = "SHA384";
		return calcSha(content, algorithm);
	}

	public byte[] calcSha512(byte[] content) throws NoSuchAlgorithmException {
		String algorithm = "SHA512";
		return calcSha(content, algorithm);
	}

	private byte[] calcSha(byte[] content, String algorithm)
			throws NoSuchAlgorithmException {
		MessageDigest md = MessageDigest.getInstance(algorithm);
		md.reset();
		md.update(content);

		byte[] output = md.digest();
		return output;
	}

	public boolean verify(CMSSignedData csd) throws Exception {
		boolean verified = true;

		Store certs = csd.getCertificates();

		SignerInformationStore signers = csd.getSignerInfos();
		Collection c = signers.getSigners();
		Iterator it = c.iterator();

		while (it.hasNext()) {
			SignerInformation signer = (SignerInformation) it.next();
			SignerId sid = signer.getSID();

			Collection certCollection = certs.getMatches(signer.getSID());
			if (certCollection.size() > 1) {
				return false;
			}
			Iterator itCert = certCollection.iterator();
			X509CertificateHolder signCertHolder = (X509CertificateHolder) itCert
					.next();
			X509Certificate signCert = new JcaX509CertificateConverter()
					.setProvider("BC").getCertificate(signCertHolder);

			verified = signer.verify(signCert.getPublicKey(), "BC");
			if (!verified) {
				return false;
			}

		}
		return verified;
	}

	public X509Certificate loadCertFromP12(String certFilePath, String passwd)
			throws KeyStoreException, IOException, NoSuchAlgorithmException,
			CertificateException, FileNotFoundException {
		return loadCertFromP12(new java.io.FileInputStream(certFilePath), passwd);
	}

	
	public X509Certificate loadCertFromP12(java.io.InputStream is, String passwd)
			throws KeyStoreException, IOException, NoSuchAlgorithmException,
			CertificateException, FileNotFoundException {
		X509Certificate x509 = null;
		java.security.KeyStore ks = java.security.KeyStore
				.getInstance("PKCS12");
		ks.load(is, passwd.toCharArray());
		// ks.load(new java.io.FileInputStream(certFilePath),null);

		Enumeration<String> aliases = ks.aliases();
		String nextAlias = "";
		while (aliases.hasMoreElements()) {
			try {
				nextAlias = aliases.nextElement();
				PrivateKey pk = (PrivateKey) ks.getKey(nextAlias,
						passwd.toCharArray());
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
	
	
	public PrivateKey loadPrivFromP12(String certFilePath, String passwd)
			throws KeyStoreException, IOException, NoSuchAlgorithmException,
			CertificateException, FileNotFoundException {
		
		return loadPrivFromP12(new java.io.FileInputStream(certFilePath), passwd);
	}

	
	public PrivateKey loadPrivFromP12(InputStream is, String passwd)
			throws KeyStoreException, IOException, NoSuchAlgorithmException,
			CertificateException, FileNotFoundException {
		PrivateKey pk = null;
		java.security.KeyStore ks = java.security.KeyStore
				.getInstance("PKCS12");
		ks.load(is, passwd.toCharArray());
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
	
	
	private static byte[] getBytesFromFile(File file) throws IOException {
		InputStream is = null;
		byte[] ret = null;
		try {
			long length = file.length();
			if (length > MAXLENGTH)
				throw new IllegalArgumentException("File is too big");
			ret = new byte[(int) length];
			is = new FileInputStream(file);
			is.read(ret);
		} finally {
			if (is != null)
				try {
					is.close();
				} catch (IOException ex) {
				}
		}
		return ret;
	}

	private byte[] loadEnv(String envPath) throws FileNotFoundException,
			IOException {
		File f = new File(envPath);
		if (!f.exists()) {
			(IttruLoggerFactory.get()).println("Não existe: " + envPath);
		}
		byte[] buffer = new byte[(int) f.length()];
		DataInputStream in = new DataInputStream(new FileInputStream(f));
		in.readFully(buffer);
		in.close();
		return buffer;
	}
}
