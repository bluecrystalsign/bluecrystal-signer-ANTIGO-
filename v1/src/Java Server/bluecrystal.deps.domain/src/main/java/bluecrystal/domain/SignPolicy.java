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

package bluecrystal.domain;

public class SignPolicy {
	private byte[] policyHash;
	private String policyUri;
	private String policyId;
	public SignPolicy(byte[] policyHash, String policyUri, String policyId) {
		super();
		this.policyHash = policyHash;
		this.policyUri = policyUri;
		this.policyId = policyId;
	}
	public byte[] getPolicyHash() {
		return policyHash;
	}
	public String getPolicyUri() {
		return policyUri;
	}
	public String getPolicyId() {
		return policyId;
	}
	
}
