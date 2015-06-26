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
import java.util.Date;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import sun.misc.BASE64Encoder;
import bluecrystal.example.web.domain.SignRef;
import bluecrystal.example.web.util.Convert;
import bluecrystal.service.v1.icpbr.IcpbrService;
import bluecrystal.service.v1.icpbr.IcpbrService_Service;

import com.google.gson.Gson;

/**
 * Servlet implementation class LoadSignature
 */
@WebServlet("/LoadSignatureNoSP")
public class LoadSignatureNoSP extends HttpServlet {
	private static final long serialVersionUID = 1L;
	private IcpbrService serv;
       
    /**
     * @see HttpServlet#HttpServlet()
     */
    public LoadSignatureNoSP() {
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
//		String certb64 = (String) request.getParameter("cert");
//		String alg = (String) request.getParameter("alg");
		
		System.out.println("LoadSignatureNoSP *****");
//		System.out.println("certb64 :"+certb64);
//		System.out.println("alg :"+alg);

		
		String destPathname = (String)request.getSession().getAttribute("destPathname");
		byte[] content = Convert.readFile(destPathname);
		PrintWriter out = response.getWriter();
		BASE64Encoder b64enc = new BASE64Encoder();
		
		out.print(b64enc.encode(content));
		out.flush();
		
	}

	

}
