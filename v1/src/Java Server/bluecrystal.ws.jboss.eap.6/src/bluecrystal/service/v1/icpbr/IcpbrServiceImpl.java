package bluecrystal.service.v1.icpbr;

import java.io.ByteArrayInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Map;

import javax.jws.HandlerChain;
import javax.jws.WebService;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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

@WebService(
endpointInterface = "bluecrystal.service.v1.icpbr.IcpbrService",
portName = "icpbrPort",
serviceName = "icpbrService")
@HandlerChain(file="handler-chain.xml")
public class IcpbrServiceImpl implements IcpbrService {
	static final Logger LOG = LoggerFactory.getLogger(IcpbrServiceImpl.class);
	private CryptoService ccServ = null;
	private SignVerifyService verify = null;
	private CertificateService certServ = null;
	private ValidatorSrv validatorServ = null;

	public static final int NDX_SHA1 = 0;
	public static final int NDX_SHA224 = 1;
	public static final int NDX_SHA256 = 2;
	public static final int NDX_SHA384 = 3;
	public static final int NDX_SHA512 = 4;

	public IcpbrServiceImpl() {
		super();
		ccServ = new CryptoServiceImpl();
		verify = new SignVerifyService();
		certServ = new CertificateService();
		validatorServ = new Validator();
		LogDebug("SignServiceImpl: " + "(" + ccServ + ")" + "(" + verify + ")"
				+ "(" + certServ + ")" + "(" + validatorServ + ")");
	}

	public String hashSignedAttribADRB10(String origHashB64, Date signingTime,
			String x509B64) throws Exception {

		LogDebug("hashSignedAttribSha1: " + "\norigHashB64 (" + origHashB64
				+ ")" + "\nsigningTime(" + signingTime + ")" + "\nx509B64("
				+ x509B64 + ")");

		try {
			BASE64Decoder b64dec = new BASE64Decoder();
			byte[] origHash = b64dec.decodeBuffer(origHashB64);
			byte[] x509 = b64dec.decodeBuffer(x509B64);
			X509Certificate cert = loadCert(x509);

			byte[] ret = ccServ.hashSignedAttribSha1(origHash, signingTime,
					cert);

			BASE64Encoder b64enc = new BASE64Encoder();
			return b64enc.encode(ret);
		} catch (Exception e) {
			LOG.error("ERRO: ", e);
			throw e;
		}

	}

	public String hashSignedAttribADRB21(String origHashB64, Date signingTime,
			String x509B64) throws Exception {
		LogDebug("hashSignedAttribSha256: " + "\norigHashB64 (" + origHashB64
				+ ")" + "\nsigningTime(" + signingTime + ")" + "\nx509B64("
				+ x509B64 + ")");
		try {
			BASE64Decoder b64dec = new BASE64Decoder();
			byte[] origHash = b64dec.decodeBuffer(origHashB64);
			byte[] x509 = b64dec.decodeBuffer(x509B64);
			X509Certificate cert = loadCert(x509);

			byte[] ret = ccServ.hashSignedAttribSha256(origHash, signingTime,
					cert);

			BASE64Encoder b64enc = new BASE64Encoder();
			return b64enc.encode(ret);
		} catch (Exception e) {
			LOG.error("ERRO: ", e);
			throw e;
		}
	}

	public String extractSignature(String signB64) throws Exception {
		LogDebug("extractSignature: " + "\nsignB64 (" + signB64 + ")");
		try {
			BASE64Decoder b64dec = new BASE64Decoder();
			byte[] sign = b64dec.decodeBuffer(signB64);

			byte[] ret = ccServ.extractSignature(sign);

			BASE64Encoder b64enc = new BASE64Encoder();
			return b64enc.encode(ret);
		} catch (Exception e) {
			LOG.error("ERRO: ", e);
			throw e;
		}
	}

	public String composeEnvelopeADRB10(String signB64, String x509B64,
			String origHashB64, Date signingTime) throws Exception {
		LogDebug("composeBodySha1: " + "\nsignB64 (" + signB64 + ")"
				+ "\nx509B64 (" + x509B64 + ")" + "\norigHashB64 ("
				+ origHashB64 + ")" + "\nsigningTime (" + signingTime + ")");
		try {
			BASE64Decoder b64dec = new BASE64Decoder();
			byte[] sign = b64dec.decodeBuffer(signB64);
			byte[] origHash = b64dec.decodeBuffer(origHashB64);
			byte[] x509 = b64dec.decodeBuffer(x509B64);
			X509Certificate cert = loadCert(x509);

			byte[] ret = ccServ.composeBodySha1(sign, cert, origHash,
					signingTime);

			byte[] hashSa = ccServ.hashSignedAttribSha1(origHash, signingTime,
					cert);

			if (!verifySign(NDX_SHA1, cert, ccServ.calcSha1(hashSa), sign)) {
				throw new InvalidSigntureException();
			}

			BASE64Encoder b64enc = new BASE64Encoder();
			return b64enc.encode(ret);
		} catch (Exception e) {
			LOG.error("ERRO: ", e);
			throw e;
		}
	}

	public String composeEnvelopeADRB21(String signB64, String x509B64,
			String origHashB64, Date signingTime) throws Exception {
		LogDebug("composeBodySha256: " + "\nsignB64 (" + signB64 + ")"
				+ "\nx509B64 (" + x509B64 + ")" + "\norigHashB64 ("
				+ origHashB64 + ")" + "\nsigningTime (" + signingTime + ")");
		try {
			BASE64Decoder b64dec = new BASE64Decoder();
			byte[] sign = b64dec.decodeBuffer(signB64);
			byte[] origHash = b64dec.decodeBuffer(origHashB64);
			byte[] x509 = b64dec.decodeBuffer(x509B64);
			X509Certificate cert = loadCert(x509);

			byte[] ret = ccServ.composeBodySha256(sign, cert, origHash,
					signingTime);

			byte[] hashSa = ccServ.hashSignedAttribSha256(origHash,
					signingTime, cert);

			if (!verifySign(NDX_SHA256, cert, ccServ.calcSha256(hashSa), sign)) {
				throw new InvalidSigntureException();
			}

			BASE64Encoder b64enc = new BASE64Encoder();
			return b64enc.encode(ret);
		} catch (Exception e) {
			LOG.error("ERRO: ", e);
			throw e;
		}
	}

	public SignCompare extractSignCompare(String sign) throws Exception {
		BASE64Decoder b64dec = new BASE64Decoder();
		LogDebug("extractSignCompare: " + "\nsign (" + sign + ")");
		try {
			return ccServ.extractSignCompare(b64dec.decodeBuffer(sign));
		} catch (Exception e) {
			LOG.error("ERRO: ", e);
			throw e;
		}

	}

	public boolean validateSignatureByPolicy(String signb64, String psb64)
			throws Exception {
		LogDebug("extractSignCompare: " + "\nsignb64 (" + signb64 + ")"
				+ "\npsb64 (" + psb64 + ")");
		try {
			BASE64Decoder b64dec = new BASE64Decoder();
			byte[] sign = b64dec.decodeBuffer(signb64);
			byte[] ps = (psb64 != null && psb64.length() > 0) ? b64dec
					.decodeBuffer(signb64) : null;
			SignCompare sc = ccServ.extractSignCompare(sign);
			if (ps == null) {
				ps = ExternalLoaderHttp.getfromUrl(sc.getPsUrl());
			}
			SignPolicyRef spr = ccServ.extractVerifyRefence(ps);

			return ccServ.validateSignatureByPolicy(spr, sc);
		} catch (Exception e) {
			LOG.error("ERRO: ", e);
			throw e;
		}

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
		LogDebug("extractSignCompare: " + "\nsignb64 (" + signb64 + ")");
		try {
			BASE64Decoder b64dec = new BASE64Decoder();
			BASE64Encoder b64enc = new BASE64Encoder();
			byte[] sign = b64dec.decodeBuffer(signb64);
			X509Certificate certEE = certServ.decodeEE(sign);
			return b64enc.encode(certEE.getEncoded());
		} catch (Exception e) {
			LOG.error("ERRO: ", e);
			throw e;
		}
	}

	public String getCertSubject(String cert) throws Exception {
		LogDebug("getCertSubject: " + "\ncert (" + cert + ")");
		try {

			Map<String, String> certEE = validatorServ
					.parseCertificateAsMap(cert);

			return certEE.get("subject0");
		} catch (Exception e) {
			LOG.error("ERRO: ", e);
			throw e;
		}

	}

	public String getCertSubjectCn(String cert) throws Exception {
		LogDebug("getCertSubject: " + "\ncert (" + cert + ")");
		try {

			Map<String, String> certEE = validatorServ
					.parseCertificateAsMap(cert);

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
		} catch (Exception e) {
			LOG.error("ERRO: ", e);
			throw e;
		}

	}

	public boolean validateSign(String signCms, String origHashb64, Date dtSign,
			boolean verifyCRL) throws Exception {
		LogDebug("validateSign: " + "\n signCms (" + signCms + ")"
				+ "\n content (" + origHashb64 + ")" + "\n dtSign (" + dtSign + ")"
				+ "\n verifyCRL (" + verifyCRL + ")");
		try {
			BASE64Decoder b64dec = new BASE64Decoder();
			byte[] sign = b64dec.decodeBuffer(signCms);
			byte[] origHash = b64dec.decodeBuffer(origHashb64);

			return ccServ.validateSign(sign, origHash, dtSign, verifyCRL);
		} catch (Exception e) {
			LOG.error("ERRO: ", e);
			throw e;
		}
	}

	public NameValue[] parseCertificate(String certificate) throws Exception {

		LogDebug("parseCertificate: " + "\n certificate (" + certificate + ")");

		try {
			return validatorServ.parseCertificate(certificate);
		} catch (Exception e) {
			LOG.error("ERRO: ", e);
			throw e;
		}
	}

	private void LogDebug(String str) {
		LOG.debug(str);
//		System.out.println(new Date() + " - "+str);
	}
}
