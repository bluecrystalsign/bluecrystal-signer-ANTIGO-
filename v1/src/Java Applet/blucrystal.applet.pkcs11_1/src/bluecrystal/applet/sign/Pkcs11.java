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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Provider.Service;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.Set;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.login.FailedLoginException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.TerminalFactory;

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;
import sun.security.pkcs.ContentInfo;
import sun.security.pkcs.PKCS7;
import sun.security.pkcs.SignerInfo;
import sun.security.pkcs11.wrapper.PKCS11Exception;
import sun.security.util.DerOutputStream;
import sun.security.x509.AlgorithmId;
import sun.security.x509.X500Name;
import bluecrystal.applet.sign.util.Base64Coder;

public class Pkcs11 {
	private static final int ALG_NO_SP = 99;

	private static final String SYSTEM32 = "\\System32\\";

	private static final String[] DIGITAL_SIGNATURE_ALGORITHM_NAME = {
			"SHA1withRSA", "SHA224withRSA", "SHA256withRSA", "SHA384withRSA",
			"SHA512withRSA" };

	public static final int STORE_PKCS11 = 0;
	public static final int STORE_FILE_UI = 1;
	public static final int STORE_FILE = 2;

	private static String PKCS11Library = null;
	private static String configString;

	private static ByteArrayInputStream configStream;
	private static KeyStore keyStore;

	private static Provider pkcs11Provider;
	private String result;
	private String caption;
	private String certAlias;
	private String orig;
	private String userPIN;
	private String lastError;
	private String lastFilePath;
	private int alg;
	private int store;

	private int curKeySize;
	private String curSubject;

	private String[] pkcs11LibName = null;
	private String[] otherPath = null;
	private static String name = null;

	public Pkcs11(String pkcs11LibName, String otherPath) {
		super();
		this.pkcs11LibName = pkcs11LibName.split(";");
		this.otherPath = otherPath.split(";");

		// this.fileChooser = new FileChooser();
	}

	public int getCurKeySize() {
		return curKeySize;
	}

	public String getCurSubject() {
		return curSubject;
	}

	public static KeyStore getKeyStore() {
		return keyStore;
	}

	public static String getConfigString() {
		return configString;
	}

	public String getLastFilePath() {
		return lastFilePath;
	}

	public void setLastFilePath(String lastFilePath) {
		this.lastFilePath = lastFilePath;
	}

	public int getStore() {
		return store;
	}

	public void setStore(int store) {
		this.store = store;
	}

	public int getAlg() {
		return alg;
	}

	public void setAlg(int alg) {
		this.alg = alg;
	}

	public String getLastError() {
		return lastError;
	}

	public String getUserPIN() {
		return userPIN;
	}

	public void setUserPIN(String userPIN) {
		this.userPIN = userPIN;
	}

	public void setOrig(String orig) {
		this.orig = orig;
	}

	public String getCertAlias() {
		return certAlias;
	}

	public void setCertAlias(String certAlias) {
		this.certAlias = certAlias;
	}

	public String getCaption() {
		return caption;
	}

	public void setCaption(String caption) {
		this.caption = caption;
	}

	private List<CertId> listCerts;

	public String getResult() {
		return result;
	}

	public void sign() throws Exception  {

		System.out.println("sign");
		switch (this.store) {
		case STORE_PKCS11:
			signp11();
			break;

		case STORE_FILE_UI:
			signFile();
			break;

		case STORE_FILE:
			signFile();
			break;

		default:
			System.out.println("opps " + this.store);
			break;
		}
	}
	
	private void signFile() throws Exception {
		if (this.alg != ALG_NO_SP) {
			signFileSignPol();
		} else {
			signFileNoSignPol();
		}
		if(pkcs11Provider != null){
			Security.removeProvider(pkcs11Provider.getName());
		}
	}


	private void signFileSignPol() throws Exception {
		System.out.println("signFileSignPol");

			PrivateKey privateKey = PkiHelper.loadPrivFromP12(
					this.lastFilePath, this.userPIN);
			X509Certificate certificate = PkiHelper.loadCertFromP12(
					this.lastFilePath, this.userPIN);
			System.out.println("Certificate: ");
			System.out.println(certificate.getSubjectDN().getName());
			System.out.println(certificate.getNotBefore() + " -> "+certificate.getNotAfter());
			

			performSign(privateKey, certificate);

	}

	private void performSign(PrivateKey privateKey, X509Certificate certificate)
			throws NoSuchAlgorithmException, InvalidKeyException, IOException,
			SignatureException {
		Signature sig = Signature
				.getInstance(DIGITAL_SIGNATURE_ALGORITHM_NAME[this.alg]);
		sig.initSign(privateKey);

		BASE64Decoder b64dec = new BASE64Decoder();
		BASE64Encoder b64enc = new BASE64Encoder();
		byte[] decodeOrig = b64dec.decodeBuffer(orig);
		sig.update(decodeOrig);
		byte[] dataSignature = sig.sign();

		result = b64enc.encode(dataSignature);
		System.out.print("Assinatura: ");
		System.out.println(result);

		// Verify signature
		Signature verificacion = Signature
				.getInstance(DIGITAL_SIGNATURE_ALGORITHM_NAME[this.alg]);
		verificacion.initVerify(certificate);
		verificacion.update(decodeOrig);
		if (verificacion.verify(dataSignature)) {
			println("Signature verification Succeeded!");
		} else {
			println("Signature verification FAILED!");
		}
	}

	private void signFileNoSignPol() throws Exception {
		System.out.println("signFileNoSignPol");
			// LOAD CERT
			PrivateKey privateKey = PkiHelper.loadPrivFromP12(
					this.lastFilePath, this.userPIN);
			X509Certificate certificate = PkiHelper.loadCertFromP12(
					this.lastFilePath, this.userPIN);
			// Sign data
			Signature sig = Signature
					.getInstance(DIGITAL_SIGNATURE_ALGORITHM_NAME[0]);
//			sha1 only
			sig.initSign(privateKey);
			BASE64Decoder b64dec = new BASE64Decoder();
			BASE64Encoder b64enc = new BASE64Encoder();
			sig.update(b64dec.decodeBuffer(orig));
			byte[] signedData  = sig.sign();

			  //load X500Name
	        X500Name xName      = X500Name.asX500Name(certificate.getSubjectX500Principal());
	        //load serial number
	        BigInteger serial   = certificate.getSerialNumber();
	        //laod digest algorithm
	        AlgorithmId digestAlgorithmId = new AlgorithmId(AlgorithmId.SHA_oid);
	        //load signing algorithm
	        AlgorithmId signAlgorithmId = new AlgorithmId(AlgorithmId.RSAEncryption_oid);

	        //Create SignerInfo:
	        SignerInfo sInfo = new SignerInfo(xName, serial, digestAlgorithmId, signAlgorithmId, signedData);
	        //Create ContentInfo:
//	        ContentInfo cInfo = new ContentInfo(ContentInfo.DIGESTED_DATA_OID, new DerValue(DerValue.tag_OctetString, dataToSign));
	        ContentInfo cInfo = new ContentInfo(ContentInfo.DIGESTED_DATA_OID, null);
	        //Create PKCS7 Signed data
	        PKCS7 p7 = new PKCS7(new AlgorithmId[] { digestAlgorithmId }, cInfo,
	        		new X509Certificate[]{certificate},
	                new SignerInfo[] { sInfo });
	        //Write PKCS7 to bYteArray
	        ByteArrayOutputStream bOut = new DerOutputStream();
	        p7.encodeSignedData(bOut);
	        byte[] encodedPKCS7 = bOut.toByteArray();
	        
	        result = b64enc.encode(encodedPKCS7);
			System.out.println("result:"+result);
	}

	
	
	private void signp11() throws Exception {
		if (this.alg != ALG_NO_SP) {
			signp11SignPol();
		} else {
			signp11NoSignPol();
		}
		Security.removeProvider(pkcs11Provider.getName());
	}

	private void signp11NoSignPol() throws Exception {

			// LOAD CERT
			PrivateKey privateKey = (PrivateKey) keyStore.getKey(
					this.getCertAlias(), "".toCharArray());
			X509Certificate certificate = (X509Certificate) keyStore
					.getCertificate(this.getCertAlias());
			// Sign data
			Signature sig = Signature
					.getInstance(DIGITAL_SIGNATURE_ALGORITHM_NAME[0]);
//			sha1 only
			sig.initSign(privateKey);
			BASE64Decoder b64dec = new BASE64Decoder();
			BASE64Encoder b64enc = new BASE64Encoder();
			sig.update(b64dec.decodeBuffer(orig));
			byte[] signedData  = sig.sign();

			  //load X500Name
	        X500Name xName      = X500Name.asX500Name(certificate.getSubjectX500Principal());
	        //load serial number
	        BigInteger serial   = certificate.getSerialNumber();
	        //laod digest algorithm
	        AlgorithmId digestAlgorithmId = new AlgorithmId(AlgorithmId.SHA_oid);
	        //load signing algorithm
	        AlgorithmId signAlgorithmId = new AlgorithmId(AlgorithmId.RSAEncryption_oid);

	        //Create SignerInfo:
	        SignerInfo sInfo = new SignerInfo(xName, serial, digestAlgorithmId, signAlgorithmId, signedData);
	        //Create ContentInfo:
//	        ContentInfo cInfo = new ContentInfo(ContentInfo.DIGESTED_DATA_OID, new DerValue(DerValue.tag_OctetString, dataToSign));
	        ContentInfo cInfo = new ContentInfo(ContentInfo.DIGESTED_DATA_OID, null);
	        //Create PKCS7 Signed data
	        PKCS7 p7 = new PKCS7(new AlgorithmId[] { digestAlgorithmId }, cInfo,
	        		new X509Certificate[]{certificate},
	                new SignerInfo[] { sInfo });
	        //Write PKCS7 to bYteArray
	        ByteArrayOutputStream bOut = new DerOutputStream();
	        p7.encodeSignedData(bOut);
	        byte[] encodedPKCS7 = bOut.toByteArray();
	        
	        result = b64enc.encode(encodedPKCS7);
	}

//	private void signp11NoSignPolWithChain() {
//		// http://security.stackexchange.com/questions/13910/pkcs7-encoding-in-java-without-external-libs-like-bouncycastle-etc
//		try {
//			// LOAD CERT
//			PrivateKey privateKey = (PrivateKey) keyStore.getKey(
//					this.getCertAlias(), "".toCharArray());
//			X509Certificate certificate = (X509Certificate) keyStore
//					.getCertificate(this.getCertAlias());
//
//			X509Certificate[] chain = loadCertChain();
//
//			// Sign data
//			Signature sig = Signature
//					.getInstance(DIGITAL_SIGNATURE_ALGORITHM_NAME[0]);
////			sha1 only
//			sig.initSign(privateKey);
//			BASE64Decoder b64dec = new BASE64Decoder();
//			BASE64Encoder b64enc = new BASE64Encoder();
//			sig.update(b64dec.decodeBuffer(orig));
//			byte[] signedData  = sig.sign();
//
//			  //load X500Name
//	        X500Name xName      = X500Name.asX500Name(certificate.getSubjectX500Principal());
//	        //load serial number
//	        BigInteger serial   = certificate.getSerialNumber();
//	        //laod digest algorithm
//	        AlgorithmId digestAlgorithmId = new AlgorithmId(AlgorithmId.SHA_oid);
//	        //load signing algorithm
//	        AlgorithmId signAlgorithmId = new AlgorithmId(AlgorithmId.RSAEncryption_oid);
//
//	        //Create SignerInfo:
//	        SignerInfo sInfo = new SignerInfo(xName, serial, digestAlgorithmId, signAlgorithmId, signedData);
//	        //Create ContentInfo:
////	        ContentInfo cInfo = new ContentInfo(ContentInfo.DIGESTED_DATA_OID, new DerValue(DerValue.tag_OctetString, dataToSign));
//	        ContentInfo cInfo = new ContentInfo(ContentInfo.DIGESTED_DATA_OID, null);
//	        //Create PKCS7 Signed data
//	        PKCS7 p7 = new PKCS7(new AlgorithmId[] { digestAlgorithmId }, cInfo,
//	        		chain,
//	                new SignerInfo[] { sInfo });
//	        //Write PKCS7 to bYteArray
//	        ByteArrayOutputStream bOut = new DerOutputStream();
//	        p7.encodeSignedData(bOut);
//	        byte[] encodedPKCS7 = bOut.toByteArray();
//	        
//	        result = b64enc.encode(encodedPKCS7);
//
//		} catch (Exception e) {
//			e.printStackTrace();
//		}
//
//	}
	
	private X509Certificate[] loadCertChain() throws Exception {
		Certificate[] chain = keyStore
				.getCertificateChain(this.getCertAlias());
		X509Certificate[] chainX509 = new X509Certificate[chain.length];
		
		for(int i = 0; i < chain.length; i++){
			chainX509[i] = (X509Certificate) chain[i];
		}
		return chainX509;
	}

	private void signp11SignPol() throws Exception {

			// LOAD CERT
			PrivateKey privateKey = (PrivateKey) keyStore.getKey(
					this.getCertAlias(), "".toCharArray());
			X509Certificate certificate = (X509Certificate) keyStore
					.getCertificate(this.getCertAlias());

//			// Sign data
//			Signature sig = Signature
//					.getInstance(DIGITAL_SIGNATURE_ALGORITHM_NAME[this.alg]);
//			sig.initSign(privateKey);
//			BASE64Decoder b64dec = new BASE64Decoder();
//			BASE64Encoder b64enc = new BASE64Encoder();
//			sig.update(b64dec.decodeBuffer(orig));
//			byte[] dataSignature = sig.sign();
//
//			result = b64enc.encode(dataSignature);
//			System.out.print("Assinatura: ");
//			System.out.println(result);
//
//			// Verify signature
//			Signature verificacion = Signature
//					.getInstance(DIGITAL_SIGNATURE_ALGORITHM_NAME[this.alg]);
//			verificacion.initVerify(certificate);
//			verificacion.update(b64dec.decodeBuffer(orig));
//			if (verificacion.verify(dataSignature)) {
//				println("Signature verification Succeeded!");
//			} else {
//				println("Signature verification FAILED!");
//			}

			performSign(privateKey, certificate);			

	}

	public int getSlot() throws Exception {

		// "Fabrica" de Terminais PC/SC
		TerminalFactory factory;
		// Lista de Leitores PC/SC
		List terminals;

		// Adquire Fabrica de Leitores
		factory = TerminalFactory.getDefault();

		// Adquire Lista de Leitores PC/SC no Sistema
		terminals = factory.terminals().list();
		// Logger.print(false, "Lista : " + terminals);

		int i = 0;
		for (Object next : terminals) {
			CardTerminal t = (CardTerminal) next;
			// System.out.print(t.getName());
			// System.out.println(t.isCardPresent() ? " COM" : " sem");
			if (t.isCardPresent()) {
				break;
				// card = t.connect("*");
				// CardChannel channel = card.getBasicChannel();
				//
				// int cn = channel.getChannelNumber();
				// System.out.println("getChannelNumber(): "+cn);
				// System.out.println("Protocol: "+card.getProtocol());
			}
			i++;

		}

		return i;
	}

	void loadKeyStore() throws Exception {
		System.out.println("loadKeyStore");
		switch (this.store) {
		case STORE_PKCS11:
			loadKeyStorep11();
			break;

		case STORE_FILE_UI:
			loadKeyStoreFileUi();
			break;

		case STORE_FILE:
			loadKeyStoreFile();
			break;

		default:
			System.out.println("opps " + this.store);
			break;
		}
	}

	private void loadKeyStoreFileUi() {
		try {
			KeyStore fileStore = KeyStore.getInstance("pkcs12", "SunJSSE");

			FileChooser fileChooser = new FileChooser();
			this.lastFilePath = fileChooser.choose();
			File f = new File(this.lastFilePath);
			if (this.lastFilePath != null && f.isFile() && f.exists()
					&& f.isAbsolute()) {
				fileStore.load(new FileInputStream(this.lastFilePath), this
						.getUserPIN().toCharArray());
				keyStore = fileStore;
			}
			this.lastError = "";

		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			this.lastError = e.getLocalizedMessage();
		}

	}

	private void loadKeyStoreFile() throws Exception {
		try {
			KeyStore fileStore = KeyStore.getInstance("pkcs12", "SunJSSE");
			if (this.lastFilePath == null || this.lastFilePath.length() == 0) {
				FileChooser fileChooser = new FileChooser();
				this.lastFilePath = fileChooser.choose();
			}
			File f = new File(this.lastFilePath);
			if (this.lastFilePath != null && f.isFile() && f.exists()
					&& f.isAbsolute()) {
				fileStore.load(new FileInputStream(this.lastFilePath), this
						.getUserPIN().toCharArray());
				keyStore = fileStore;
			}
			this.lastError = "";

		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			this.lastError = e.getLocalizedMessage();
		}
	}

	private void loadKeyStorep11() throws KeyStoreException, IOException,
			NoSuchAlgorithmException, CertificateException {

		System.out.println("loadKeyStorep11");
		name = "ittru";

		String systemWindowsDir = System.getenv("SystemRoot") + SYSTEM32;

		List<String> paths = new ArrayList<String>();
		if (systemWindowsDir != null) {
			paths.add(systemWindowsDir);
		}
		for (String next : this.otherPath) {
			paths.add(verifyPath(next));
		}

		for (String nextPath : paths) {
			for (String next : pkcs11LibName) {
				try {
					PKCS11Library = nextPath + next;
					System.out.println("Carregando: " + PKCS11Library);
					createConfigSlotListIndex();
					// Load SunPKCS#11 provider
					pkcs11Provider = new sun.security.pkcs11.SunPKCS11(
							configStream);

					Security.addProvider(pkcs11Provider);
					keyStore = KeyStore.getInstance("PKCS11");

					System.out.println("** FOUND!");
					printDebug();
					break;
				} catch (Exception e) {
					System.out.println("Ex: "+e.getLocalizedMessage());
				}
			}
		}

		try {
			keyStore.load(null, userPIN.toCharArray());
			this.lastError = "";
		} catch (Exception e) {
			// TODO Auto-generated catch block
			if (e instanceof IOException) {
				IOException io = (IOException) e;
				FailedLoginException fl = (FailedLoginException) e.getCause();
				PKCS11Exception p1ex = (PKCS11Exception) fl.getCause();
				System.out.println(p1ex.getMessage());
				this.lastError = p1ex.getMessage();
			}
		}

	}

	private String verifyPath(String next) {
		if (!next.endsWith(File.separator)) {
			next = next.concat(File.separator);
		}
		return next;
	}

	private void printDebug() {
		Enumeration<Object> el = pkcs11Provider.elements();
		System.err.println(" ** ELEMENTS ***");
		while (el.hasMoreElements()) {
			Object obj = el.nextElement();
			System.err.println("OBJ: " + obj);
		}
		Set<Object> chaves = pkcs11Provider.keySet();
		System.err.println(" ** CHAVES ***");
		for (Object nextKey : chaves) {
			System.err.println("OBJ: " + nextKey);
		}
		System.err.println("INFO: " + pkcs11Provider.getInfo());
		System.err.println("NAME: " + pkcs11Provider.getName());
		pkcs11Provider.list(System.err);
		Set<Service> services = pkcs11Provider.getServices();
		for (Object nextObj : services.toArray()) {
			Service nextServ = (Service) nextObj;
			System.err.println(" ** SERVICE ***");
			System.err.println("Alg: " + nextServ.getAlgorithm());
			System.err.println("Class: " + nextServ.getClassName());
			System.err.println("Type: " + nextServ.getType());
			Provider prov = nextServ.getProvider();
			System.err.println(" ** PROVIDER ***");
			System.err.println("INFO: " + prov.getInfo());
			System.err.println("NAME: " + prov.getName());
			System.err.println("VERS: " + prov.getVersion());
		}
		pkcs11Provider.getInfo();
	}

	private void println(String string) {
		System.out.println("* " + string);

	}

	void createConfigSlotListIndex() {
		name = "ittru";

		int i = -1;
		try {
			i = getSlot();
		} catch (Exception e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		String slotTxt = String.format("\n slotListIndex  = %d ", i);

		String ext = "attributes(*,*,*)=\n{\nCKA_TOKEN=true\nCKA_LOCAL=true\n}";
		// Compose configuration file
		configString = "name = " + name.replace(' ', '_') + "\n" + "library = "
				+ PKCS11Library + slotTxt +
				// "\n slotListIndex  = 5 " + // Please define correct
				// SlotID here
				// + PKCS11Library + "\n slot = -1 " + // Please define correct
				"\n attributes = compatibility \n" + ext;
		// println(configString);

		// System.err.print("CONFIG:" + configString);

		byte[] configBytes = configString.getBytes();
		configStream = new ByteArrayInputStream(configBytes);
	}

	public String loadCertsJson() {
		String ret = "";
		for (CertId next : this.listCerts) {
			ret += String.format("{\"alias\":\"%s\",\"subject\":\"%s\"},\n",
					next.getAlias(), next.getSubjectDn());
			System.out.println("ret:"+ret);
		}
		
		System.out.println("ret:"+ret);
		//ret = ret.replace(ret.substring(ret.length() - 2), "");
		ret = ret.substring(0, ret.length() - 2);
		System.out.println("ret:"+ret);
		return "[\n" + ret + "]\n";
	}

	public void refreshCerts() {
		this.listCerts = new ArrayList<CertId>();
		try {
			// loadKeyStore();

			int numCerts = 0;
			String alias = "";
			Enumeration aliasesEnum = keyStore.aliases();
			while (aliasesEnum.hasMoreElements()) {
				alias = (String) aliasesEnum.nextElement();
				Certificate cert = keyStore.getCertificate(alias);
				X509Certificate x509Certificate = (X509Certificate) cert;
				RSAPublicKey rsaPubK = (RSAPublicKey) x509Certificate
						.getPublicKey();
				this.listCerts.add(new CertId(alias, x509Certificate
						.getSubjectDN().getName(), cert.getEncoded(), rsaPubK
						.getModulus().bitLength()));
				numCerts++;
			}

		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	}

	public String getCert(String alias) {

		debugPrn("* list cert# : " + this.listCerts.size());
		for (CertId next : this.listCerts) {
			debugPrn(next.getAlias());
			if (next.getAlias().compareToIgnoreCase(alias) == 0) {
				return new String(Base64Coder.encode(next.getEncoded()));
			}
		}
		return null;
	}

	private static SecretKey decryptAESKey(byte[] data, PrivateKey priv) {
		SecretKey key = null;
		Cipher cipher = null;

		try {
			// initialize the cipher...
			cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			cipher.init(Cipher.DECRYPT_MODE, priv);

			// generate the aes key!
			key = new SecretKeySpec(cipher.doFinal(data), "AES");
		} catch (Exception e) {
			String x = "exception decrypting the aes key: " + e.getMessage();
			debugPrn(x);
			return null;
		}

		return key;
	}

	private static void debugPrn(String x) {
		System.out.println(x);
	}

	void skeyDercypt() throws Exception {

		System.out.println("sign");
		switch (this.store) {
		case STORE_PKCS11:
			skeyDercyptP11();
			break;

		case STORE_FILE_UI:
			skeyDercyptFile();
			break;

		case STORE_FILE:
			skeyDercyptFile();
			break;

		default:
			System.out.println("opps " + this.store);
			break;
		}
	}

	private void skeyDercyptP11() throws Exception {

		PrivateKey privateKey = (PrivateKey) keyStore.getKey(
				this.getCertAlias(), "".toCharArray());

		byte[] origBin = (new BASE64Decoder()).decodeBuffer(this.orig);

		SecretKey Skey = decryptAESKey(origBin, privateKey);
		this.result = new String(
				(new BASE64Encoder()).encode(Skey.getEncoded()));
	}

	private void skeyDercyptFile() throws Exception {

		PrivateKey privateKey = PkiHelper.loadPrivFromP12(this.lastFilePath,
				this.userPIN);
		byte[] origBin = (new BASE64Decoder()).decodeBuffer(this.orig);

		SecretKey Skey = decryptAESKey(origBin, privateKey);
		this.result = new String(
				(new BASE64Encoder()).encode(Skey.getEncoded()));
	}

	public static String conv(byte[] byteArray) {
		StringBuffer result = new StringBuffer();
		for (byte b : byteArray) {
			result.append(String.format("%02X", b));
		}
		return result.toString();
	}

	public int getKeySize(String alias) {
		for (CertId next : this.listCerts) {
			if (next.getAlias().compareToIgnoreCase(alias) == 0) {
				return next.getKeySize();
			}
		}
		return 0;
	}

	public String getSubject(String alias) {
		for (CertId next : this.listCerts) {
			debugPrn(next.getAlias());
			if (next.getAlias().compareToIgnoreCase(alias) == 0) {
				return next.getSubjectDn();
			}
		}
		return null;
	}

}
