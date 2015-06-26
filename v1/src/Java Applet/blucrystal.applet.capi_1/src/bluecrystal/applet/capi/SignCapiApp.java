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

package bluecrystal.applet.capi;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URL;

import com.sun.jna.Native;
import com.sun.jna.NativeLibrary;

public class SignCapiApp {
	public static void main(String[] args) {
		new SignCapiApp().showDll();
	    }

	private void showDll() {
		System.out.println("JVM: "+System.getProperty("sun.arch.data.model") +" bits");
		
		
		iSignCapi INSTANCE = loadDll();
//		INSTANCE.doPrintIt();
		
		String certificate = INSTANCE.getCertificate("", "", "", "" );
		System.out.println(certificate);
		System.out.println(INSTANCE.sign(0, "saValue"));
		System.out.println(INSTANCE.getKeySize());
		System.out.println(INSTANCE.getSubject());
	            
		INSTANCE =null;
	}

	iSignCapi loadDll() {
//		try {
//			LoaderUtil lu = new LoaderUtil();
//			File dll = lu.loadFile();
//            
//            System.out.println("Path to file: "+dll.getAbsolutePath());
//            
//            NativeLoader nl = new NativeLoader();
//			 return nl.loadNative(dll);
//		} catch (Exception e) {
//			// TODO Auto-generated catch block
//			e.printStackTrace();
//		}
		return null;
	}
	
}
