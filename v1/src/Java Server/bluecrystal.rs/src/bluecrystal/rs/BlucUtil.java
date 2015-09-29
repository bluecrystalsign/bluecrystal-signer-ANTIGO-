package bluecrystal.rs;

import java.io.ByteArrayInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;
import java.util.Map;
import java.util.regex.Pattern;

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;
import bluecrystal.domain.NameValue;
import bluecrystal.domain.SignCompare;
import bluecrystal.domain.SignPolicyRef;
import bluecrystal.service.exception.InvalidSigntureException;
import bluecrystal.service.loader.ExternalLoaderHttp;
import bluecrystal.service.service.CertificateService;
import bluecrystal.service.service.CryptoService;
import bluecrystal.service.service.CryptoServiceImpl;
import bluecrystal.service.service.SignVerifyService;
import bluecrystal.service.service.Validator;
import bluecrystal.service.service.ValidatorSrv;

public class BlucUtil {

	private CryptoService ccServ = null;
	private SignVerifyService verify = null;
	private CertificateService certServ = null;
	private ValidatorSrv validatorServ = null;

	public static final int NDX_SHA1 = 0;
	public static final int NDX_SHA224 = 1;
	public static final int NDX_SHA256 = 2;
	public static final int NDX_SHA384 = 3;
	public static final int NDX_SHA512 = 4;

	private static final int FALLBACK_LIMIT = 2048;

	public BlucUtil() {
		super();
		ccServ = new CryptoServiceImpl();
		verify = new SignVerifyService();
		certServ = new CertificateService();
		validatorServ = new Validator();
	}

	boolean validarECompletarPacoteAssinavel(byte[] certificado, byte[] sha1,
			byte[] sha256, byte[] assinatura, boolean politica,
			Date dtAssinatura, EnvelopeResponse resp) throws Exception {
		X509Certificate c = loadCert(certificado);
		RSAPublicKey pubKey = (RSAPublicKey) c.getPublicKey();

		byte[] sign = assinatura;

		resp.setCn(obterNomeExibicao(getCN(certificado)));
		setDetails(certificado, resp.getCertdetails());

		if (pubKey.getModulus().bitLength() == FALLBACK_LIMIT) {
			resp.setEnvelope(composeEnvelopeADRB21(sign, c.getEncoded(),
					sha256, dtAssinatura));
			resp.setPolicy("AD-RB");
			resp.setPolicyversion("2.1");
			resp.setPolicyoid("2.16.76.1.7.1.1.2.1");
		} else {
			resp.setEnvelope(composeEnvelopeADRB10(sign, c.getEncoded(), sha1,
					dtAssinatura));
			resp.setPolicy("AD-RB");
			resp.setPolicyversion("1.0");
			resp.setPolicyoid("2.16.76.1.7.1.1.1");
		}
		return true;
	}

	boolean produzPacoteAssinavel(byte[] certificado, byte[] sha1,
			byte[] sha256, boolean politica, Date dtAssinatura,
			HashResponse resp) throws Exception {

		X509Certificate c = loadCert(certificado);

		resp.setCn(obterNomeExibicao(getCN(certificado)));
		setDetails(certificado, resp.getCertdetails());

		RSAPublicKey pubKey = (RSAPublicKey) c.getPublicKey();

		if (!politica) {
			BASE64Encoder b64enc = new BASE64Encoder();
			resp.setHash(b64enc.encode(sha1));
			resp.setPolicy("PKCS#7");
			return true;
		}

		if (pubKey.getModulus().bitLength() >= FALLBACK_LIMIT) {
			resp.setHash(hashSignedAttribADRB21(sha256, dtAssinatura,
					c.getEncoded()));
			resp.setPolicy("AD-RB");
			resp.setPolicyversion("2.1");
			resp.setPolicyoid("2.16.76.1.7.1.1.2.1");
		} else {
			resp.setHash(hashSignedAttribADRB10(sha1, dtAssinatura,
					c.getEncoded()));
			resp.setPolicy("AD-RB");
			resp.setPolicyversion("1.0");
			resp.setPolicyoid("2.16.76.1.7.1.1.1");
		}

		return true;
	}

	boolean validateSign(byte[] assinatura, byte[] sha1, byte[] sha256,
			Date dtAssinatura, boolean verificarLCRs, ValidateResponse resp)
			throws Exception {
		String politica = obtemPolitica(assinatura);

		X509Certificate certEE = certServ.decodeEE(assinatura);

		byte[] certificate = certEE.getEncoded();
		resp.setCn(obterNomeExibicao(getCN(certificate)));
		setDetails(certificate, resp.getCertdetails());

		if (politica == null) {
			boolean f = ccServ.validateSign(assinatura, sha1, dtAssinatura,
					verificarLCRs);
			if (!f) {
				resp.setError("Não foi possível validar a assinatura digital");
				return false;
			}
			return true;
		} else {
			int keyLength = 1024;

			if (resp.getCertdetails().containsKey("key_length0"))
				keyLength = Integer.parseInt(resp.getCertdetails().get(
						"key_length0"));

			byte[] origHash;
			if (keyLength < 2048)
				origHash = sha1;
			else
				origHash = sha256;

			boolean f = ccServ.validateSign(assinatura, origHash, dtAssinatura,
					verificarLCRs);
			if (!f) {
				resp.setError("Não foi possível validar a assinatura digital");
				return false;
			}

			f = validateSignatureByPolicy(assinatura, null);
			if (!f) {
				resp.setError("Não foi possíel validar a assinatura com política");
				return false;
			}
			String policyName = recuperarNomePolitica(politica);
			if (policyName != null) {
				String pol[] = policyName.split(" v");
				resp.setPolicy(pol[0]);
				resp.setPolicyversion(pol[1]);
			}
			resp.setPolicyoid(politica);
			return true;
		}
	}

	private String getCN(byte[] certificate) throws Exception {
		BASE64Encoder b64enc = new BASE64Encoder();
		String sCert = b64enc.encode(certificate);
		return getCertSubjectCn(sCert);
	}

	private void setDetails(byte[] certificate, Map<String, String> map)
			throws Exception {
		BASE64Encoder b64enc = new BASE64Encoder();
		String sCert = b64enc.encode(certificate);
		NameValue[] l = parseCertificate(sCert);

		for (NameValue nv : l) {
			map.put(nv.getName(), nv.getValue());
		}
	}

	private String hashSignedAttribADRB10(byte[] origHash, Date signingTime,
			byte[] x509) throws Exception {
		X509Certificate cert = loadCert(x509);

		byte[] ret = ccServ.hashSignedAttribSha1(origHash, signingTime, cert);

		BASE64Encoder b64enc = new BASE64Encoder();
		return b64enc.encode(ret);
	}

	private String hashSignedAttribADRB21(byte[] origHash, Date signingTime,
			byte[] x509) throws Exception {
		X509Certificate cert = loadCert(x509);

		byte[] ret = ccServ.hashSignedAttribSha256(origHash, signingTime, cert);

		BASE64Encoder b64enc = new BASE64Encoder();
		return b64enc.encode(ret);
	}

	private String extractSignature(String signB64) throws Exception {
		BASE64Decoder b64dec = new BASE64Decoder();
		byte[] sign = b64dec.decodeBuffer(signB64);

		byte[] ret = ccServ.extractSignature(sign);

		BASE64Encoder b64enc = new BASE64Encoder();
		return b64enc.encode(ret);
	}

	private String composeEnvelopeADRB10(byte[] sign, byte[] x509,
			byte[] origHash, Date signingTime) throws Exception {
		X509Certificate cert = loadCert(x509);

		byte[] ret = ccServ.composeBodySha1(sign, cert, origHash, signingTime);

		byte[] hashSa = ccServ
				.hashSignedAttribSha1(origHash, signingTime, cert);

		if (!verifySign(NDX_SHA1, cert, ccServ.calcSha1(hashSa), sign)) {
			throw new InvalidSigntureException();
		}

		BASE64Encoder b64enc = new BASE64Encoder();
		return b64enc.encode(ret);
	}

	private String composeEnvelopeADRB21(byte[] sign, byte[] x509,
			byte[] origHash, Date signingTime) throws Exception {
		X509Certificate cert = loadCert(x509);

		byte[] ret = ccServ
				.composeBodySha256(sign, cert, origHash, signingTime);

		byte[] hashSa = ccServ.hashSignedAttribSha256(origHash, signingTime,
				cert);

		if (!verifySign(NDX_SHA256, cert, ccServ.calcSha256(hashSa), sign)) {
			throw new InvalidSigntureException();
		}

		BASE64Encoder b64enc = new BASE64Encoder();
		return b64enc.encode(ret);
	}

	private SignCompare extractSignCompare(String sign) throws Exception {
		BASE64Decoder b64dec = new BASE64Decoder();
		return ccServ.extractSignCompare(b64dec.decodeBuffer(sign));
	}

	private String obtemPolitica(byte[] assinatura) {
		String politica = null;
		try {
			SignCompare sc = ccServ.extractSignCompare(assinatura);

			politica = sc.getPsOid();
		} catch (Exception e) {
		}
		return politica;
	}

	private static String obterNomeExibicao(String s) {
		s = s.split(",")[0];
		// Retira o CPF, se houver
		String[] splitted = s.split(":");
		if (splitted.length == 2
				&& Pattern.compile("[0-9]{11}").matcher(splitted[1]).matches())
			return splitted[0];
		return s;
	}

	private String recuperarNomePolitica(String politica) {
		switch (politica) {
		case "2.16.76.1.7.1.1.1":
			return "AD-RB v1.0";
		case "2.16.76.1.7.1.2.1":
			return "AD-RT v1.0";
		case "2.16.76.1.7.1.3.1":
			return "AD-RV v1.0";
		case "2.16.76.1.7.1.4.1":
			return "AD-RC v1.0";
		case "2.16.76.1.7.1.5.1":
			return "AD-RA v1.0";
		case "2.16.76.1.7.1.1.2.1":
			return "AD-RB v2.1";
		case "2.16.76.1.7.1.2.2.1":
			return "AD-RT v2.1";
		case "2.16.76.1.7.1.3.2.1":
			return "AD-RV v2.1";
		case "2.16.76.1.7.1.4.2.1":
			return "AD-RC v2.1";
		case "2.16.76.1.7.1.5.2.1":
			return "AD-RA v2.1";
		}
		return politica;
	}

	private boolean validateSignatureByPolicy(byte[] sign, byte[] ps)
			throws Exception {
		SignCompare sc = ccServ.extractSignCompare(sign);
		if (ps == null) {
			ps = ExternalLoaderHttp.getfromUrl(sc.getPsUrl());
		}
		SignPolicyRef spr = ccServ.extractVerifyRefence(ps);

		return ccServ.validateSignatureByPolicy(spr, sc);
	}

	private X509Certificate loadCert(byte[] certEnc)
			throws FileNotFoundException, CertificateException, IOException {
		InputStream is = new ByteArrayInputStream(certEnc);
		CertificateFactory cf = CertificateFactory.getInstance("X509");
		X509Certificate c = (X509Certificate) cf.generateCertificate(is);
		is.close();
		return c;
	}

	protected boolean verifySign(int hashId, X509Certificate cert,
			byte[] contentHash, byte[] sigBytes) throws Exception {
		return verify.verify(hashId, contentHash, sigBytes, cert);
	}

	public String extractSignerCert(String signb64) throws Exception {
		BASE64Decoder b64dec = new BASE64Decoder();
		BASE64Encoder b64enc = new BASE64Encoder();
		byte[] sign = b64dec.decodeBuffer(signb64);
		X509Certificate certEE = certServ.decodeEE(sign);
		return b64enc.encode(certEE.getEncoded());
	}

	public String getCertSubject(String cert) throws Exception {
		Map<String, String> certEE = validatorServ.parseCertificateAsMap(cert);

		return certEE.get("subject0");
	}

	public String getCertSubjectCn(String cert) throws Exception {
		Map<String, String> certEE = validatorServ.parseCertificateAsMap(cert);

		String[] rdnList = certEE.get("subject0").split(",");

		for (String nextRdn : rdnList) {
			if (nextRdn.startsWith("CN")) {
				String[] cnRdn = (nextRdn.trim()).split("=");
				if (cnRdn.length == 2) {
					return cnRdn[1];
				}
			}
		}

		return null;
	}

	public NameValue[] parseCertificate(String certificate) throws Exception {
		return validatorServ.parseCertificate(certificate);
	}
}
