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

package bluecrystal.service.v1.rebuilder;

import javax.jws.HandlerChain;
import javax.jws.WebService;

import org.bouncycastle.util.encoders.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import bluecrystal.service.service.CmsWithChainService;

@WebService(
endpointInterface = "bluecrystal.service.v1.rebuilder.EnvelopeRebuilderService",
portName = "envelopeRebuilderPort",
serviceName = "envelopeRebuilderService")
@HandlerChain(file="handler-chain.xml")
public class EnvelopeRebuildServiceImpl implements EnvelopeRebuilderService {
	static final Logger LOG = LoggerFactory.getLogger(EnvelopeRebuildServiceImpl.class);
	private CmsWithChainService cmsWithChain = null;

	public static final int CMS_WITH_CHAIN = 0;

	public EnvelopeRebuildServiceImpl() {
		super();
		cmsWithChain = new CmsWithChainService();
	}

	@Override
	public String rebuildEnvelope(int format, String envelopeb64)
			throws Exception {
		byte[] ret = null;
		Base64 b64 = new Base64();
		
		switch (format) {
		case CMS_WITH_CHAIN:
			ret = cmsWithChain.rebuildEnvelope(b64.decode(envelopeb64));
			break;

		default:
			break;
		}
		
		return new String( b64.encode(ret) );
	}

}
