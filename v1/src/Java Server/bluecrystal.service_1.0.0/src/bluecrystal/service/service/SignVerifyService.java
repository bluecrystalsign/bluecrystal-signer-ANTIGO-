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
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DigestInfo;
import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA224Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.encodings.PKCS1Encoding;
import org.bouncycastle.crypto.engines.RSABlindedEngine;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import bluecrystal.bcdeps.helper.DerEncoder;
import bluecrystal.domain.helper.IttruLoggerFactory;
import bluecrystal.service.helper.Utils;

public class SignVerifyService {
	static final Logger LOG = LoggerFactory.getLogger(SignVerifyService.class);

	
	public SignVerifyService() {
		super();
	}
	
	
	public static String [] algName = {"SHA1withRSA", "SHA224withRSA", "SHA256withRSA", "SHA384withRSA", "SHA512withRSA"};

	public boolean verify(int hashId, byte[] contentHash, byte[] sigBytes, X509Certificate cert)
			throws Exception {
		RSAPublicKey pubK = (RSAPublicKey) cert.getPublicKey();
		CipherParameters param = new RSAKeyParameters(false, pubK.getModulus(), pubK.getPublicExponent());
		RSABlindedEngine cipher2 = new RSABlindedEngine();
		cipher2.init(false, param);
		AsymmetricBlockCipher cipher = new PKCS1Encoding(cipher2);
		byte[] sig = cipher.processBlock(sigBytes, 0, sigBytes.length);
		AlgorithmIdentifier algId = createAlgorithm(hashId);
		byte[] expected = derEncode(contentHash, algId);

        LOG.debug("Sig:("+sigBytes.length+")"+Utils.conv(sigBytes));
        LOG.debug("Has:("+contentHash.length+")"+Utils.conv(contentHash));
        LOG.debug("Sig:("+sig.length+")"+Utils.conv(sig));
        LOG.debug("Exp:("+expected.length+")"+Utils.conv(expected));
		
		
		if (sig.length == expected.length) {
			for (int i = 0; i < sig.length; i++) {
				if (sig[i] != expected[i]) {
					return false;
				}
			}
		}
		else if (sig.length == expected.length - 2)  // NULL left out
        {
            int sigOffset = sig.length - contentHash.length - 2;
            int expectedOffset = expected.length - contentHash.length - 2;

            expected[1] -= 2;      // adjust lengths
            expected[3] -= 2;

            for (int i = 0; i < contentHash.length; i++)
            {
                if (sig[sigOffset + i] != expected[expectedOffset + i])  // check hash
                {
                    return false;
                }
            }

            for (int i = 0; i < sigOffset; i++)
            {
                if (sig[i] != expected[i])  // check header less NULL
                {
                    return false;
                }
            }
        }
        else
        {
            return false;
        }

        return true;

	}


	
	private AlgorithmIdentifier createAlgorithm(int hashId) throws Exception {
		return DerEncoder.createAlgorithm(hashId);
	}

	private byte[] derEncode(byte[] contentHash, AlgorithmIdentifier algId)
			throws Exception {
		DigestInfo dInfo = new DigestInfo(algId, contentHash);
		byte[] encoded = encodeDigest(dInfo);
		return encoded;
	}

	private byte[] encodeDigest(DigestInfo dInfo) throws IOException {
		return DerEncoder.encodeDigest(dInfo);
	}

	private Digest getHashById(int hashId) {
		Digest ret = null;
		switch (hashId) {
		case DerEncoder.NDX_SHA1:
			ret = new SHA1Digest();
			break;
		case DerEncoder.NDX_SHA224:
			ret = new SHA224Digest();
			break;
		case DerEncoder.NDX_SHA256:
			ret = new SHA256Digest();
			break;
		case DerEncoder.NDX_SHA384:
			ret = new SHA384Digest();
			break;
		case DerEncoder.NDX_SHA512:
			ret = new SHA512Digest();
			break;
		default:
			break;
		}
		return ret;
	}

}
