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

import com.google.gson.Gson;

import bluecrystal.service.v1.icpbr.IcpbrService;
import bluecrystal.service.v1.icpbr.IcpbrService_Service;
import bluecrystal.service.v1.icpbr.NameValue;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.List;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;



/**
 * Servlet implementation class LoadSignature
 */
@WebServlet("/ParseCert")
public class ParseCert extends HttpServlet {
	private static final long serialVersionUID = 1L;
	private IcpbrService serv;
       
    /**
     * @see HttpServlet#HttpServlet()
     */
    public ParseCert() {
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
		String certb64 = (String) request.getParameter("cert");
		
		System.out.println("Parse Cert *****");
		System.out.println("certb64 :"+certb64);
		
		List<NameValue> parsed = serv.parseCertificate(certb64);
		for(NameValue next : parsed){
			System.out.println(next.getName() + " -> "+ next.getValue());
		}
		Gson gson = new Gson();
		String parsedJson = gson.toJson(parsed);
		
		PrintWriter out = response.getWriter();
		out.print(parsedJson);
		out.flush();

	}

	

}
