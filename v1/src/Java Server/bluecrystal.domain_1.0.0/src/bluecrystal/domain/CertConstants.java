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

public class CertConstants {
	
	public static final String EKU_D = "eku%d";

	public static final String KU_D = "ku%d";

	public static final String SAN_EMAIL_D = "san_email%d";

	public static final String BASIC_CONSTRAINT_D = "basicConstraint%d";

	public static final String KEY_LENGTH_D = "key_length%d";

	public static final String SERIAL_D = "serial%d";

	public static final String CERT_SHA256_D = "certSha256%d";

	public static final String VERSION_D = "version%d";

	public static final String NOT_BEFORE_D = "notBefore%d";

	public static final String NOT_AFTER_D = "notAfter%d";

	public static final String ISSUER_D = "issuer%d";

	public static final String SUBJECT_D = "subject%d";
	
	public static final String OCSP_STR = "ocsp%d";
	public static final String CA_ISSUERS_STR = "chain%d";
	public static final String AKI_FMT = "aki%d";
	public static final String CRL_DP = "crlDP%d";
	
	public static final String CERT_POL_OID = "certPolOid%d";
	public static final String CERT_POL_QUALIFIER = "certPolQualifier%d";
	
	public static final String CERT_USAGE_D = "cert_usage%d";
	public static final String BIRTH_DATE_D = "birth_date%d";
	public static final String CPF_D = "cpf%d";
	public static final String PIS_D = "pis%d";
	public static final String RG_D = "rg%d";
	public static final String RG_ORG_D = "rg_org%d";
	public static final String RG_UF_D = "rg_uf%d";
	public static final String PERSON_NAME_D = "person_name%d";
	public static final String CNPJ_D = "cnpj%d";
	public static final String ELEITOR_D = "eleitor%d";
	public static final String ZONA_D = "zona%d";
	public static final String SECAO_D = "secao%d";
	public static final String INSS_D = "inss%d";
	public static final String OAB_REG_D = "oab_reg%d";
	public static final String OAB_UF_D = "oab_uf%d";
	public static final String PROFESSIONAL_D = "professional%d";
	public static final String UPN_D = "upn%d";
}
