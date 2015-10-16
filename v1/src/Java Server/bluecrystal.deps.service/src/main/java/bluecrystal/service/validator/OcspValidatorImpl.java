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

package bluecrystal.service.validator;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;

import org.bouncycastle.ocsp.BasicOCSPResp;
import org.bouncycastle.ocsp.OCSPException;
import org.bouncycastle.ocsp.OCSPReq;
import org.bouncycastle.ocsp.OCSPResp;
import org.bouncycastle.ocsp.OCSPRespStatus;
import org.bouncycastle.ocsp.RevokedStatus;
import org.bouncycastle.ocsp.SingleResp;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import bluecrystal.bcdeps.helper.DerEncoder;
import bluecrystal.domain.CertStatus;
import bluecrystal.domain.StatusConst;
import bluecrystal.service.exception.OCSPQueryException;
import bluecrystal.service.exception.RevokedException;
import bluecrystal.service.exception.UndefStateException;

public class OcspValidatorImpl implements OcspValidator {
	static final Logger LOG = LoggerFactory.getLogger(OcspValidatorImpl.class);

	static final long ONE_MINUTE_IN_MILLIS=60000;//millisecs
	static final long MIN_VALID=60*ONE_MINUTE_IN_MILLIS;//millisecs
	
	
	public OcspValidatorImpl() {
		super();
	}	
	
	public CertStatus verifyOCSP(X509Certificate nextCert,
			X509Certificate nextIssuer, Date date) throws IOException,
			CertificateException, CRLException, UndefStateException,
			RevokedException {
		try {
			OCSPReq req = GenOcspReq(nextCert, nextIssuer);

			List<String> OCSPUrls = extractOCSPUrl(nextCert);

			OCSPResp ocspResponse = null;
			for (String ocspUrl : OCSPUrls) {
				try {
					ocspResponse = xchangeOcsp(ocspUrl, req);
					break;
				} catch (Exception e) {
					LOG.error("Error exchanging OCSP",e);
				}
			}
			if (ocspResponse != null) {
				Date valid = xtractNextUpdate(ocspResponse);
				if (valid != null) {
					return new CertStatus(StatusConst.GOOD, valid);
				} else {
					Date goodUntil = new Date();
					goodUntil = new Date(goodUntil.getTime() + MIN_VALID);
					return new CertStatus(StatusConst.GOOD, goodUntil);
				}
			}

		} catch (OCSPException e) {
			LOG.error("Error executing OCSP Operation",e);
		} catch (OCSPQueryException e) {
			LOG.error("Error executing OCSP Operation",e);
		}
		return new CertStatus(StatusConst.UNKNOWN, null);
	}

	private Date xtractNextUpdate(OCSPResp ocspResponse) throws OCSPQueryException {
		switch (ocspResponse.getStatus()) {
		case OCSPRespStatus.SUCCESSFUL:
			break;
		case OCSPRespStatus.INTERNAL_ERROR:
		case OCSPRespStatus.MALFORMED_REQUEST:
		case OCSPRespStatus.SIGREQUIRED:
		case OCSPRespStatus.TRY_LATER:
		case OCSPRespStatus.UNAUTHORIZED:
			
			throw new OCSPQueryException(
					"OCSP Error: " //$NON-NLS-1$
					+ Integer.toString(ocspResponse.getStatus()));
		default:
			throw new OCSPQueryException("***"); //$NON-NLS-1$
		}

		try {
			BasicOCSPResp bresp = (BasicOCSPResp) ocspResponse
					.getResponseObject();

			if (bresp == null) {
				throw new OCSPQueryException("***"); //$NON-NLS-1$
			}
//			X509Certificate[] ocspcerts = bresp.getCerts(Messages
//					.getString("ValidateSignAndCertBase.71")); //$NON-NLS-1$

			// Verify all except trusted anchor
			// for (i = 0; i < ocspcerts.length - 1; i++) {
			// ocspcerts[i].verify(ocspcerts[i + 1].getPublicKey());
			// }
			// if (rootcert != null) {
			// ocspcerts[i].verify(rootcert.getPublicKey());
			// }

			SingleResp[] certstat = bresp.getResponses();
			for (SingleResp singleResp : certstat) {
				// if (singleResp.getCertStatus() == null) {
				// return true;
				// }
				if (singleResp.getCertStatus() instanceof RevokedStatus) {
					throw new RevokedException();
				}
				return singleResp.getNextUpdate();
			}

		} catch (Exception e) {
			throw new OCSPQueryException(e);
		}

		return null;
	}

	private OCSPResp xchangeOcsp(String ocspUrl, OCSPReq req)
			throws MalformedURLException, IOException, OCSPQueryException {
		URL url = new URL(ocspUrl);
		HttpURLConnection con = (HttpURLConnection) url.openConnection();

		con.setAllowUserInteraction(false);
		con.setDoInput(true);
		con.setDoOutput(true);
		con.setUseCaches(false);
		con.setInstanceFollowRedirects(false);
		con.setRequestMethod("POST"); //$NON-NLS-1$

		con
				.setRequestProperty(
						"Content-Length", Integer.toString(req //$NON-NLS-1$
										.getEncoded().length));
		con
				.setRequestProperty(
						"Content-Type", "application/ocsp-request"); //$NON-NLS-1$ //$NON-NLS-2$

		con.connect();
		OutputStream os = con.getOutputStream();
		os.write(req.getEncoded());
		os.close();

		if (con.getResponseCode() != HttpURLConnection.HTTP_OK) {
			throw new OCSPQueryException("Server did not respond with HTTP_OK(200) but with "
					+ con.getResponseCode());
		}

		if ((con.getContentType() == null)
				|| !con.getContentType().equals(
						"application/ocsp-response")) { //$NON-NLS-1$
			throw new OCSPQueryException("Response MIME type is not application/ocsp-response"); //$NON-NLS-1$
		}

		// Read response
		InputStream reader = con.getInputStream();

		int resplen = con.getContentLength();
		byte[] ocspResponseEncoded = new byte[resplen];

		int offset = 0;
		int bread;
		while ((resplen > 0)
				&& (bread = reader.read(ocspResponseEncoded, offset, resplen)) != -1) {
			offset += bread;
			resplen -= bread;
		}

		reader.close();
		con.disconnect();
		return new OCSPResp(ocspResponseEncoded);
	}
	
	
	private OCSPReq GenOcspReq(X509Certificate nextCert,
			X509Certificate nextIssuer) throws OCSPException {

	return DerEncoder.GenOcspReq(nextCert, nextIssuer);
	}

	private List<String> extractOCSPUrl(X509Certificate nextCert)
			throws CRLException {
		return DerEncoder.extractOCSPUrl(nextCert);
	}
}
