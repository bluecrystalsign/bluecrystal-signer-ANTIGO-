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

package bluecrystal.applet.sign;

public class CertId {
	private String alias;
	private String subjectDn;
	private byte[] encoded;
	private int keySize;


	public byte[] getEncoded() {
		return encoded;
	}
//	public CertId(String alias, String subjectDn, byte[] encoded, ) {
//		super();
//		this.alias = alias;
//		this.subjectDn = subjectDn;
//		this.encoded = encoded;
//	}
	public String getAlias() {
		return alias;
	}
	public int getKeySize() {
		return keySize;
	}
	public String getSubjectDn() {
		return subjectDn;
	}
	public CertId(String alias, String subjectDn, byte[] encoded, int keySize) {
		super();
		this.alias = alias;
		this.subjectDn = subjectDn;
		this.encoded = encoded;
		this.keySize = keySize;
	}

	
}
