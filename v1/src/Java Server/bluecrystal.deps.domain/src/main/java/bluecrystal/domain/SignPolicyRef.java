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

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

public class SignPolicyRef {
//	notBefore -> 20120307000000Z
//	mandatedSignedAttr.0 -> 1.2.840.113549.1.9.3
//	mandatedSignedAttr.2 -> 1.2.840.113549.1.9.16.2.15
//	mandatedCertificateRef -> 1
//	mandatedSignedAttr.1 -> 1.2.840.113549.1.9.4
//	psHashAlg -> 2.16.840.1.101.3.4.2.1
//	mandatedSignedAttr.3 -> 1.2.840.113549.1.9.16.2.47
//	psOid -> 2.16.76.1.7.1.1.2.1
//	notAfter -> 20230621000000Z
//	polIssuerName -> C=BR,O=ICP-Brasil,OU=Instituto Nacional de Tecnologia da Informacao - ITI
//	dateOfIssue -> 20120307000000Z
	
	
private Date notBefore;
private Date notAfter;
private Date dateOfIssue;
private List<String> mandatedSignedAttr;
private int mandatedCertificateRef;
private String psHashAlg;
private String psOid;
private String polIssuerName;
private String fieldOfApplication;


public String getFieldOfApplication() {
	return fieldOfApplication;
}
public void setFieldOfApplication(String fieldOfApplication) {
	this.fieldOfApplication = fieldOfApplication;
}
public Date getNotBefore() {
	return notBefore;
}
public void setNotBefore(Date notBefore) {
	this.notBefore = notBefore;
}
public Date getNotAfter() {
	return notAfter;
}
public void setNotAfter(Date notAfter) {
	this.notAfter = notAfter;
}
public Date getDateOfIssue() {
	return dateOfIssue;
}
public void setDateOfIssue(Date dateOfIssue) {
	this.dateOfIssue = dateOfIssue;
}
public List<String> getMandatedSignedAttr() {
	return mandatedSignedAttr;
}
public void addMandatedSignedAttr(String mandatedSignedAttr) {
	if(this.mandatedSignedAttr == null ){
		this.mandatedSignedAttr = new ArrayList<String>();
	}
	this.mandatedSignedAttr.add(mandatedSignedAttr);
}
@Override
public String toString() {
	return "SignPolicyRef [notBefore=" + notBefore + ",\n"
			+ " notAfter=" + notAfter + ",\n"
			+ "dateOfIssue=" + dateOfIssue + ",\n"
			+ " mandatedSignedAttr=" + mandatedSignedAttr + ",\n"
			+ " mandatedCertificateRef="+ mandatedCertificateRef + ",\n"
			+ " psHashAlg=" + psHashAlg + ",\n"
			+ " psOid="+ psOid + ",\n"
			+ " polIssuerName=" + polIssuerName + "]";
}
public int getMandatedCertificateRef() {
	return mandatedCertificateRef;
}
public void setMandatedCertificateRef(int mandatedCertificateRef) {
	this.mandatedCertificateRef = mandatedCertificateRef;
}
public String getPsHashAlg() {
	return psHashAlg;
}
public void setPsHashAlg(String psHashAlg) {
	this.psHashAlg = psHashAlg;
}
public String getPsOid() {
	return psOid;
}
public void setPsOid(String psOid) {
	this.psOid = psOid;
}
public String getPolIssuerName() {
	return polIssuerName;
}
public void setPolIssuerName(String polIssuerName) {
	this.polIssuerName = polIssuerName;
}
	
	
	
	
}
