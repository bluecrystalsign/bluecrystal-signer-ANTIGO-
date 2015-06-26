using System;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Windows.Forms;
using Microsoft.Win32;

namespace Kosmala.Michal.ActiveXTest
{
	/// <summary>
	/// Summary description for Class1.
	/// </summary>
	[ProgId("Dendrite.WebForce.MMP.Web.OurActiveX")]
	[ClassInterface(ClassInterfaceType.AutoDual), ComSourceInterfaces(typeof(ControlEvents))] //Implementing interface that will be visible from JS
	[Guid("121C3E0E-DC6E-45dc-952B-A6617F0FAA32")]
	[ComVisible(true)]
	public class ActiveXObject
	{
		private string myParam = "Empty"; 

		public ActiveXObject()
		{
			
		}

		public event ControlEventHandler OnClose;

		/// <summary>
		/// Opens application. Called from JS
		/// </summary>
		[ComVisible(true)]
		public void Open()
		{
			//TODO: Replace the try catch in aspx with try catch below. The problem is that js OnClose does not register.
			try
			{
				
				MessageBox.Show(myParam); //Show param that was passed from JS
				Thread.Sleep(2000); //Wait a little before closing. This is just to show the gap between calling OnClose event.
				Close(); //Close application

			}
			catch (Exception e)
			{
				//ExceptionHandling.AppException(e);
				throw e;
			}
		}

		/// <summary>
		/// Parameter visible from JS
		/// </summary>
		[ComVisible(true)]
		public string MyParam
		{
			get
			{
				return myParam;
			}
			set
			{
				myParam = value;
			}
		}
	

		[ComVisible(true)]
		public void Close()
		{
			if(OnClose != null)
			{
				OnClose("http://otherwebsite.com"); //Calling event that will be catched in JS
			}
			else
			{
				MessageBox.Show("No Event Attached"); //If no events are attached send message.
			}
		}
		

	
		///	<summary>
		///	Register the class as a	control	and	set	it's CodeBase entry
		///	</summary>
		///	<param name="key">The registry key of the control</param>
		[ComRegisterFunction()]
		public static void RegisterClass ( string key )
		{
			// Strip off HKEY_CLASSES_ROOT\ from the passed key as I don't need it
			StringBuilder	sb = new StringBuilder ( key ) ;
			
			sb.Replace(@"HKEY_CLASSES_ROOT\","") ;
			// Open the CLSID\{guid} key for write access
			RegistryKey k	= Registry.ClassesRoot.OpenSubKey(sb.ToString(),true);

			// And create	the	'Control' key -	this allows	it to show up in
			// the ActiveX control container
			RegistryKey ctrl = k.CreateSubKey	( "Control"	) ;
			ctrl.Close ( ) ;

			// Next create the CodeBase entry	- needed if	not	string named and GACced.
			RegistryKey inprocServer32 = k.OpenSubKey	( "InprocServer32" , true )	;
			inprocServer32.SetValue (	"CodeBase" , Assembly.GetExecutingAssembly().CodeBase )	;
			inprocServer32.Close ( ) ;
				// Finally close the main	key
			k.Close (	) ;
			MessageBox.Show("Registered");
		}

		///	<summary>
		///	Called to unregister the control
		///	</summary>
		///	<param name="key">Tke registry key</param>
		[ComUnregisterFunction()]
		public static void UnregisterClass ( string	key	)
		{
			StringBuilder	sb = new StringBuilder ( key ) ;
			sb.Replace(@"HKEY_CLASSES_ROOT\","") ;

			// Open	HKCR\CLSID\{guid} for write	access
			RegistryKey	k =	Registry.ClassesRoot.OpenSubKey(sb.ToString(),true);

			// Delete the 'Control'	key, but don't throw an	exception if it	does not exist
			k.DeleteSubKey ( "Control" , false ) ;

			// Next	open up	InprocServer32
			//RegistryKey	inprocServer32 = 
			k.OpenSubKey (	"InprocServer32" , true	) ;

			// And delete the CodeBase key,	again not throwing if missing
			k.DeleteSubKey ( "CodeBase"	, false	) ;

			// Finally close the main key
			k.Close	( )	;
			MessageBox.Show("UnRegistered");
		}



	}

	/// <summary>
	/// Event handler for events that will be visible from JavaScript
	/// </summary>
	public delegate void ControlEventHandler(string redirectUrl); 


	/// <summary>
	/// This interface shows events to javascript
	/// </summary>
	[Guid("68BD4E0D-D7BC-4cf6-BEB7-CAB950161E79")]
	[InterfaceType(ComInterfaceType.InterfaceIsIDispatch)]
	public interface ControlEvents
	{
		//Add a DispIdAttribute to any members in the source interface to specify the COM DispId.
		[DispId(0x60020001)]
		void OnClose(string redirectUrl); //This method will be visible from JS
	}
}
