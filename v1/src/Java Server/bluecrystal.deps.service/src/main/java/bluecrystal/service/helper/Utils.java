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

package bluecrystal.service.helper;

import java.io.ByteArrayInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.bouncycastle.util.encoders.Base64;

import bluecrystal.service.exception.LicenseNotFoundExeception;
import bluecrystal.service.interfaces.RepoLoader;
import bluecrystal.service.loader.Messages;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Utils {
	static final Logger LOG = LoggerFactory.getLogger(Utils.class);
	
	static private	RepoLoader repoLoader;
	private static String loaderType = Messages.getString("RepoLoader.loaderType");
	
	
	static {
		try {
			repoLoader = (RepoLoader) Class
			        .forName(loaderType)
			        .newInstance();
			if(repoLoader==null){
				LOG.error("Could not load Repoloader ");
			}
		} catch (Exception e) {
			LOG.error("Could not load Repoloader ", e);
		}
	}
	
	protected static final String ID_SHA1 = "1.3.14.3.2.26";
	
	protected static final int ALG_SHA1 = 0;
	protected static final int ALG_SHA224 = 1;
	protected static final int ALG_SHA256 = 2;
	protected static final int ALG_SHA384 = 3;
	protected static final int ALG_SHA512 = 4;	
	
	
	
	public static X509Certificate loadCertFromRepo(String certFilePath)
	throws Exception {
		List<X509Certificate> certList = listCertFromRepo(certFilePath);
		return certList.get(0);
	}
	public static List<X509Certificate> listCertFromRepo(String certFilePath)
			throws Exception {
		String[] fileList =  null;
		if(!repoLoader.exists(certFilePath)){
			if(!repoLoader.exists(certFilePath+".txt")){
				if(!repoLoader.exists(certFilePath+".cer")){
					throw new FileNotFoundException(repoLoader.getFullPath(certFilePath));
				} else {
					certFilePath = certFilePath+".cer";
				}
			} else {
				certFilePath = certFilePath+".txt";
			}
		}
		
		if(repoLoader.isDir(certFilePath)  ){
			fileList = repoLoader.list(certFilePath);
		} else {
			fileList = new String[1];
			fileList[0] = certFilePath;
		}
		List<X509Certificate> retList = new ArrayList<X509Certificate>();
		for(String next : fileList){
			try {
				retList.addAll(listCertFromFile(next));
			} catch (Exception e) {
				LOG.error("Could not add certs from Repo "+next, e);
			}
		}
		return retList;
	}	
	
	public static List<X509Certificate> listCertFromFile(String certFilePath)
			throws Exception {
		InputStream is = null;
		List<X509Certificate> retList = new ArrayList<X509Certificate>();
		try {
			is = repoLoader.load(certFilePath);
		} catch (LicenseNotFoundExeception e) {
		}
		 CertificateFactory cf = CertificateFactory.getInstance("X509");
		 Collection<? extends Certificate> c = 
		 cf.generateCertificates(is);
		 for(Certificate next: c){
			 retList.add((X509Certificate)next);
		 }
		return retList;
	}	
	
	
	public static String conv(byte[] byteArray){
		StringBuffer result = new StringBuffer();
		for (byte b:byteArray) {
		    result.append(String.format("%02X", b));
		}
		return result.toString();
	}

	
	public static byte[] convHexToByte(String content)  {
		byte[] signbyte;
		content = content.trim();
		String[] signList = splitHex(content);
		signbyte = conv(signList);
		return signbyte;
	}	
	
	private static String[] splitHex(String content) {
		String[] ret = null;
		int len = content.length();
		if(len % 2 == 0){
			ret = new String[len/2];
			for(int i = 0; i < len/2; i++){
				ret[i] = content.substring(i*2, (i+1)*2);
			}
		}
			
		return ret;
	}
	private static byte[] conv(String[] certList) {
		byte[] certbyte = new byte[certList.length];

		for (int i = 0; i < certbyte.length; i++) {
			certbyte[i] = conv(certList[i]);
		}
		return certbyte;
	}
	
	private static byte conv(String hex) {
		int i = Integer.parseInt(hex, 16);
		byte c = (byte) i;
		return c;
	}	
		
	public static int hashAlgToId(String hashAlg){
		
		int hashId = 0;
		
		if(hashAlg.compareToIgnoreCase("SHA1")==0){
			hashId = ALG_SHA1;
		} else if(hashAlg.compareToIgnoreCase("SHA224")==0){
			hashId = ALG_SHA224;
		} else if(hashAlg.compareToIgnoreCase("SHA256")==0){
			hashId = ALG_SHA256;
		} else if(hashAlg.compareToIgnoreCase("SHA384")==0){
			hashId = ALG_SHA384;
		} else if(hashAlg.compareToIgnoreCase("SHA512")==0){
			hashId = ALG_SHA512;
		}  
		return hashId;
	}
	
	public static X509Certificate createCert(String b64Enc) throws Exception {
		ByteArrayInputStream bais = new ByteArrayInputStream(Base64.decode(b64Enc.getBytes()));
		 CertificateFactory cf = CertificateFactory.getInstance("X509");
		 Certificate cert = 
		 cf.generateCertificate(bais);
		 return (X509Certificate) cert;

	}	
	
	public static X509Certificate createCert(byte [] b) throws Exception {
		ByteArrayInputStream bais = new ByteArrayInputStream(b);
		 CertificateFactory cf = CertificateFactory.getInstance("X509");
		 Certificate cert = 
		 cf.generateCertificate(bais);
		 return (X509Certificate) cert;

	}	
//	public static String getHashAlg(int hash) throws Exception{
//		String ret = "";
//		switch (hash) {
//		case ALG_SHA1:
//			ret = ID_SHA1;
//			break;
//
//		case ALG_SHA224:
//			ret = ID_SHA1;
//			break;
//
//		case ALG_SHA256:
//			ret = ID_SHA256;
//			break;
//
//		case ALG_SHA384:
//			ret = ID_SHA384;
//			break;
//
//		case ALG_SHA512:
//			ret = ID_SHA512;
//			break;
//
//		default:
//			throw new Exception("hash alg não identificado:" + hash);
//
//		}
//		return ret;
//	}	


//	public static List<X509Certificate> listCertFromS3(String string) {
//		// TODO Auto-generated method stub
//		return null;
//	}


//	public static X509Certificate loadCertFromS3(String certName) {
//		// TODO Auto-generated method stub
//		return null;
//	}

}
