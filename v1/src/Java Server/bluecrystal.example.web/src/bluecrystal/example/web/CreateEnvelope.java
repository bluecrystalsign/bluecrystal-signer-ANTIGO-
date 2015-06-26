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

package bluecrystal.example.web;

import java.io.IOException;
import java.io.PrintWriter;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.datatype.XMLGregorianCalendar;

import sun.misc.BASE64Encoder;
import bluecrystal.example.web.domain.SignedEnvelope;
import bluecrystal.example.web.util.Convert;
import bluecrystal.service.v1.icpbr.Exception_Exception;
import bluecrystal.service.v1.icpbr.IcpbrService;
import bluecrystal.service.v1.icpbr.IcpbrService_Service;
import bluecrystal.service.v1.icpbr.Signature;

import com.google.gson.Gson;

/**
 * Servlet implementation class CreateEnvelope
 */
@WebServlet("/CreateEnvelope")
public class CreateEnvelope extends HttpServlet {
	private static final long serialVersionUID = 1L;
	private IcpbrService serv;
       
    /**
     * @see HttpServlet#HttpServlet()
     */
    public CreateEnvelope() {
        super();
        serv = (new IcpbrService_Service()).getIcpbrPort();
    }

	/**
	 * @see HttpServlet#doGet(HttpServletRequest request, HttpServletResponse response)
	 */
	protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		try {
			handleRequest(request, response);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	/**
	 * @see HttpServlet#doPost(HttpServletRequest request, HttpServletResponse response)
	 */
	protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		try {
			handleRequest(request, response);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	private void handleRequest(HttpServletRequest request,
			HttpServletResponse response) throws Exception {
		String hash_valueb64 = (String) request.getParameter("hash_value");
		String timeValue = (String) request.getParameter("time_value");
		String saValueb64 = (String) request.getParameter("sa_value");
		String signedValueb64 = (String) request.getParameter("signed_value");
		String certb64 = (String) request.getParameter("cert");
		String alg = (String) request.getParameter("alg");
		
		
		System.out.println("CreateEnvelope *****");
		System.out.println("hash_valueb64 :"+hash_valueb64);
		System.out.println("timeValue :"+timeValue);
		System.out.println("saValueb64 :"+saValueb64);
		System.out.println("signedValueb64 :"+signedValueb64);
		System.out.println("certb64 :"+certb64);
		System.out.println("alg :"+alg);
		
		String ret = "";
		
		Boolean algSha256 = false;
		if(alg == null || alg.compareToIgnoreCase("sha256")==0){
			algSha256 = true;

			List<Signature> signatute = new ArrayList<Signature>();
			Signature sign = new Signature();
			sign.setOrigHashB64(hash_valueb64);
			sign.setSignB64(signedValueb64);
			sign.setSigningTime(parseDate(timeValue));
//			ret = serv.composeCoSignEnvelopeADRB21(signatute );

			ret = serv.composeEnvelopeADRB21(signedValueb64, certb64, hash_valueb64, parseDate(timeValue));
		} else {
			ret = serv.composeEnvelopeADRB10(signedValueb64, certb64, hash_valueb64, parseDate(timeValue));
			
		}

		
		
		boolean isOk = verifySignature(algSha256, ret, (String)request.getSession().getAttribute("destPathname"));
		String certB64 = parseCertFromSignature(ret);
		String certSubject = getCertSubject(certb64);
		Gson gson = new Gson();
		String VerifiedSignJson = gson.toJson(new SignedEnvelope(ret, isOk, certB64, certSubject));
		System.out.println("retorno: "+ VerifiedSignJson);
		
		PrintWriter out = response.getWriter();
		out.print(VerifiedSignJson);
		out.flush();
	}

	private String parseCertFromSignature(String ret) throws Exception_Exception  {
		
		return serv.extractSignerCert(ret);
	}

	private String getCertSubject(String certb64) throws Exception_Exception {
		return serv.getCertSubject(certb64);
	}

	private boolean verifySignature(Boolean algSha256, String ret, String filename) throws Exception {
		
		MessageDigest hashSum = null;
		if(algSha256){
			hashSum = MessageDigest.getInstance("SHA-256");
		} else {
			hashSum = MessageDigest.getInstance("SHA-1");
		}
		hashSum.update(Convert.readFile(filename));
		byte[] digestResult = hashSum.digest();
		
		String digestB64 = (new BASE64Encoder()).encode(digestResult);
		return serv.validateSign(ret, digestB64, Convert.asXMLGregorianCalendar(new Date()), false);
	}

	private XMLGregorianCalendar parseDate(String timeValue) throws DatatypeConfigurationException {
		Date signDate = new Date();
		signDate.setTime(Long.parseLong(timeValue));
		
		
		return Convert.asXMLGregorianCalendar(signDate);
	}
	
	


}
