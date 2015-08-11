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

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import javax.servlet.ServletException;
import javax.servlet.annotation.MultipartConfig;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.Part;

/**
 * Servlet implementation class UploadServlet
 */
@MultipartConfig
@WebServlet("/uploadServlet")
public class UploadServlet extends HttpServlet {
//	private static final String UPLOAD_PATH = 
//			System.getProperty("user.home") +  
//			Messages.getString("UploadServlet.0"); //$NON-NLS-1$
    public UploadServlet() {
		super();
//		File f = new File(UPLOAD_PATH);
//		if(!f.exists()){
//			f.mkdirs();
//		}
	}	

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        handleUpload(request, response);
    }

	private void handleUpload(HttpServletRequest request,
			HttpServletResponse response) throws IOException, ServletException {
		Part file = request.getPart(Messages.getString("UploadServlet.1")); //$NON-NLS-1$
        String filename = getFilename(file);
        InputStream filecontent = file.getInputStream();
        String destPathname = getUploadPath() + File.separator + filename;
		copyFile(filecontent, new File(destPathname));
		filecontent.close();

		
		request.getSession().setAttribute("destPathname", destPathname);
		

        response.setContentType(Messages.getString("UploadServlet.2")); //$NON-NLS-1$
        response.setCharacterEncoding(Messages.getString("UploadServlet.3")); //$NON-NLS-1$
        response.getWriter().write(Messages.getString("UploadServlet.4") + filename + Messages.getString("UploadServlet.5")); //$NON-NLS-1$ //$NON-NLS-2$
	}

	private static String getFilename(Part part) {
        for (String cd : part.getHeader(Messages.getString("UploadServlet.6")).split(Messages.getString("UploadServlet.7"))) { //$NON-NLS-1$ //$NON-NLS-2$
            if (cd.trim().startsWith(Messages.getString("UploadServlet.8"))) { //$NON-NLS-1$
                String filename = cd.substring(cd.indexOf('=') + 1).trim().replace(Messages.getString("UploadServlet.9"), Messages.getString("UploadServlet.10")); //$NON-NLS-1$ //$NON-NLS-2$
                return filename.substring(filename.lastIndexOf('/') + 1).substring(filename.lastIndexOf('\\') + 1); // MSIE fix.
            }
        }
        return null;
    }
    
	private String getUploadPath(){
		String uploadPath = 
				System.getProperty("user.home") +  
				Messages.getString("UploadServlet.0"); //$NON-NLS-1$
		File f = new File(uploadPath);
		if(!f.exists()){
			f.mkdirs();
		}
		return uploadPath;
	}
    
    private static void copyFile(InputStream input, File dest)
    		throws IOException {

    	OutputStream output = null;
    	try {
    		
    		output = new FileOutputStream(dest);
    		byte[] buf = new byte[1024];
    		int bytesRead;
    		while ((bytesRead = input.read(buf)) > 0) {
    			output.write(buf, 0, bytesRead);
    		}
    	} finally {
    		if(output != null) { output.close(); };
    	}
    }
}
