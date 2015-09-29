package bluecrystal.service.v1.icpbr;

import java.util.Date;

import javax.jws.WebParam;
import javax.jws.WebService;

import bluecrystal.domain.NameValue;
import bluecrystal.domain.SignCompare;


@WebService
public interface IcpbrService {
	
	public abstract String hashSignedAttribADRB10(
			@WebParam(name = "origHashb64")String origHashb64,
			@WebParam(name = "signingTime")Date signingTime,
			@WebParam(name = "x509")String x509) throws Exception;

	public abstract String hashSignedAttribADRB21(
			@WebParam(name = "origHashb64")String origHashb64,
			@WebParam(name = "signingTime")Date signingTime,
			@WebParam(name = "certb64")String certb64) throws Exception;

	public abstract String extractSignature(@WebParam(name = "sign")String sign) throws Exception;

	public abstract String composeEnvelopeADRB10(
			@WebParam(name = "signB64")String signb64,
			@WebParam(name = "certb64")String certb64,
			@WebParam(name = "origHashb64")String origHashb64, 
			@WebParam(name = "signingTime")Date signingTime) throws Exception;

	public abstract String composeEnvelopeADRB21(
			@WebParam(name = "signB64")String signb64,
			@WebParam(name = "certb64")String certb64,
			@WebParam(name = "origHashb64")String origHashb64, 
			@WebParam(name = "signingTime")Date signingTime) throws Exception;

	public abstract boolean validateSignatureByPolicy(
			@WebParam(name = "signCmsb64")String signCmsb64, 
			@WebParam(name = "psb64")String psb64)
			throws Exception;

	public abstract SignCompare extractSignCompare(
			@WebParam(name = "signCmsb64")String signCmsb64) throws Exception;
	
	public String getCertSubject(@WebParam(name = "certb64")String certb64) throws Exception;
	public String getCertSubjectCn(@WebParam(name = "certb64")String certb64) throws Exception;
	public boolean  validateSign(
			@WebParam(name = "signCmsb64")String signCmsb64, 
			@WebParam(name = "origHashb64")String origHashb64,
			@WebParam(name = "signingTime")Date signingTime, 
			@WebParam(name = "verifyCrlOcsp")boolean verifyCrlOcsp) throws Exception;
	
	public NameValue[] parseCertificate(@WebParam(name = "certb64")String certb64) throws Exception;
	
	public String extractSignerCert(@WebParam(name = "signCmsb64")String signCmsb64) throws Exception;
}
