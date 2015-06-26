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

import java.util.concurrent.CountDownLatch;

public class MySynch {
	CountDownLatch goGetCertificate = new CountDownLatch(1);
	CountDownLatch isEndedGetCertificate = new CountDownLatch(1);

	CountDownLatch goSign = new CountDownLatch(1);
	CountDownLatch isEndedSign = new CountDownLatch(1);

	CountDownLatch goGetKeySize = new CountDownLatch(1);
	CountDownLatch isEndedGetKeySize = new CountDownLatch(1);

	CountDownLatch goGetSubject = new CountDownLatch(1);
	CountDownLatch isEndedGetSubject = new CountDownLatch(1);

	
//	**************************
//	****** GetCertificate
//	**************************
	public void countDownGetCertificate() {
		goGetCertificate.countDown();
	}

	public void awaitGetCertificate() throws InterruptedException {
		goGetCertificate.await();
	}
	
	public void resetGetCertificate() {
		goGetCertificate = new CountDownLatch(1);
		isEndedGetCertificate = new CountDownLatch(1);
	}

	public void setEndedGetCertificate() {
		isEndedGetCertificate.countDown();		
	}
	public void getEndedGetCertificate() throws InterruptedException {
		isEndedGetCertificate.await();
	}
	
//	**************************
//	****** Sign
//	**************************
	public void countDownSign() {
		goSign.countDown();
	}

	public void awaitSign() throws InterruptedException {
		goSign.await();
	}
	
	public void resetSign() {
		goSign = new CountDownLatch(1);
		isEndedSign = new CountDownLatch(1);
	}

	public void setEndedSign() {
		isEndedSign.countDown();		
	}
	public void getEndedSign() throws InterruptedException {
		isEndedSign.await();
	}
	
//	**************************
//	****** GetKeySize
//	**************************
	public void countDownGetKeySize() {
		goGetKeySize.countDown();
	}

	public void awaitGetKeySize() throws InterruptedException {
		goGetKeySize.await();
	}
	
	public void resetGetKeySize() {
		goGetKeySize = new CountDownLatch(1);
		isEndedGetKeySize = new CountDownLatch(1);
	}

	public void setEndedGetKeySize() {
		isEndedGetKeySize.countDown();		
	}
	public void getEndedGetKeySize() throws InterruptedException {
		isEndedGetKeySize.await();
	}
	
//	**************************
//	****** GetSubject
//	**************************
	public void countDownGetSubject() {
		goGetSubject.countDown();
	}

	public void awaitGetSubject() throws InterruptedException {
		goGetSubject.await();
	}
	
	public void resetGetSubject() {
		goGetSubject = new CountDownLatch(1);
		isEndedGetSubject = new CountDownLatch(1);
	}

	public void setEndedGetSubject() {
		isEndedGetSubject.countDown();		
	}
	public void getEndedGetSubject() throws InterruptedException {
		isEndedGetSubject.await();
	}
	
	
	
	
}
