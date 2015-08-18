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



import bluecrystal.service.helper.Utils;

public class ADRBService_21 extends BaseService {

	public ADRBService_21() {
		super();
		minKeyLen = 2048;
		signingCertFallback = false;
		addChain = false;
		signedAttr = true;
//		version = 3; // CEF
		version = 1;
		policyHash = Utils
				.convHexToByte(SIG_POLICY_HASH_21);
		policyId = SIG_POLICY_BES_ID_21;
		policyUri = SIG_POLICY_URI_21;
	}
}
