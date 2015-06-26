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

package bluecrystal.applet.capi.domain;

public class GetCertificateParms {
	private String title;
	private String msg;
	private String subjectRegex;
	private String issuerRegex;
	private String ret;
	
	public String getRet() {
		return ret;
	}
	public void setRet(String ret) {
		this.ret = ret;
	}
	public GetCertificateParms(String title, String msg, String subjectRegex,
			String issuerRegex) {
		super();
		this.title = title;
		this.msg = msg;
		this.subjectRegex = subjectRegex;
		this.issuerRegex = issuerRegex;
	}
	public String getTitle() {
		return title;
	}
	public String getMsg() {
		return msg;
	}
	public String getSubjectRegex() {
		return subjectRegex;
	}
	public String getIssuerRegex() {
		return issuerRegex;
	}
	
	

}
