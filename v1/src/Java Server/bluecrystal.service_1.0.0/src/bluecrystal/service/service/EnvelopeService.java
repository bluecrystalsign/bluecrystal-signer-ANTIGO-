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

package bluecrystal.service.service;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;

import org.bouncycastle.asn1.ASN1Set;

import bluecrystal.bcdeps.helper.DerEncoder;
import bluecrystal.domain.AppSignedInfo;
import bluecrystal.domain.AppSignedInfoEx;

public interface EnvelopeService {

	// *********************************************************
	//
	// SHA1
	//
	// *********************************************************
//	public abstract byte[] hashSignedAttribSha1(String certId, byte[] origHash,
//			Date signingTime) throws Exception;
	public byte[] hashSignedAttribSha1(byte[] origHash, Date signingTime,
			X509Certificate x509) throws NoSuchAlgorithmException,
			CertificateEncodingException, Exception, IOException;
	public abstract byte[] buildFromS3Sha1(List<AppSignedInfo> listAsi, int attachSize)
			throws Exception;
	public abstract byte[] buildCms(List<AppSignedInfoEx> listAsiEx, int attachSize)
			throws Exception;
	

	// *********************************************************
	//
	// SHA224
	//
	// *********************************************************
//	public abstract byte[] hashSignedAttribSha224(String certId,
//			byte[] origHash, Date signingTime) throws Exception;
	public byte[] hashSignedAttribSha224(byte[] origHash, Date signingTime,
			X509Certificate x509) throws NoSuchAlgorithmException,
			CertificateEncodingException, Exception, IOException;
	public abstract byte[] buildFromS3Sha224(List<AppSignedInfo> listAsi, int attachSize)
			throws Exception;

	// *********************************************************
	//
	// SHA256
	//
	// *********************************************************
//	public abstract byte[] hashSignedAttribSha256(String certId,
//			byte[] origHash, Date signingTime) throws Exception;
	public byte[] hashSignedAttribSha256(byte[] origHash, Date signingTime,
			X509Certificate x509) throws NoSuchAlgorithmException,
			CertificateEncodingException, Exception, IOException;

	public abstract byte[] buildFromS3Sha256(List<AppSignedInfo> listAsi, int attachSize)
			throws Exception;

	// *********************************************************
	//
	// SHA384
	//
	// *********************************************************
//	public abstract byte[] hashSignedAttribSha384(String certId,
//			byte[] origHash, Date signingTime) throws Exception;
	public byte[] hashSignedAttribSha384(byte[] origHash, Date signingTime,
			X509Certificate x509) throws NoSuchAlgorithmException,
			CertificateEncodingException, Exception, IOException;

	public abstract byte[] buildFromS3Sha384(List<AppSignedInfo> listAsi, int attachSize)
			throws Exception;

	// *********************************************************
	//
	// SHA512
	//
	// *********************************************************
//	public abstract byte[] hashSignedAttribSha512(String certId,
//			byte[] origHash, Date signingTime) throws Exception;
	public byte[] hashSignedAttribSha512(byte[] origHash, Date signingTime,
			X509Certificate x509) throws NoSuchAlgorithmException,
			CertificateEncodingException, Exception, IOException;

	public abstract byte[] buildFromS3Sha512(List<AppSignedInfo> listAsi, int attachSize)
			throws Exception;
	
	// *********************************************************
	//
	// SignerInfo
	//
	// *********************************************************

	public abstract ASN1Set siCreate(byte[] origHash, Date signingTime, X509Certificate x509,
			DerEncoder derEnc, byte[] certHash, int idSha)
			throws Exception;

	public byte[] calcSha1(byte[] content) throws NoSuchAlgorithmException;

	public byte[] calcSha224(byte[] content) throws NoSuchAlgorithmException;

	public byte[] calcSha256(byte[] content) throws NoSuchAlgorithmException;

	public byte[] calcSha384(byte[] content) throws NoSuchAlgorithmException;

	public byte[] calcSha512(byte[] content) throws NoSuchAlgorithmException;

	public abstract boolean isProcHash();

}




