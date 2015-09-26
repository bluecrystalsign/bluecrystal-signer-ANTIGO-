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
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URL;

import com.sun.jna.Native;

public class LoaderUtil {


//	iSignCapi loadDll() {
//		try {
//			File dll = loadFile();
//            
//            System.out.println("Path to file: "+dll.getParent());
//            
//            NativeLoader nl = new NativeLoader();
//			 return nl.loadNative(dll);
//		} catch (Exception e) {
//			// TODO Auto-generated catch block
//			e.printStackTrace();
//		}
//		return null;
//	}

	public File loadFile(String dllName) throws IOException, FileNotFoundException {
		
		URL res = this.getClass().getResource(dllName);
		InputStream is = res.openStream();
		File dll = File.createTempFile("signerCapi",".dll");
		OutputStream fos = new FileOutputStream(dll);
		
		byte[] array = new byte[1024];
		for(int i=is.read(array);
		    i!=-1;
		    i=is.read(array)
		) {
		    fos.write(array,0,i);
		}

		/* Close all streams */
		fos.close();
		is.close();
		return dll;
	}

	public iSignCapi loadNative(File dll) {
		System.setProperty("jna.library.path", dll.getParent());
		return (iSignCapi) Native.loadLibrary(dll.getName(), iSignCapi.class);
	}
	
}
