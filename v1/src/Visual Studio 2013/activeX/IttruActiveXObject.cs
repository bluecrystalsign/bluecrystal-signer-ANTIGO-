using System;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Windows.Forms;
using Microsoft.Win32;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.ComponentModel;
using System.Text.RegularExpressions;
using System.Security.Cryptography.Pkcs;




namespace ittru
{
	/// <summary>
	/// Summary description for Class1.
	/// </summary>



    public enum ObjectSafetyOptions
    {
        INTERFACESAFE_FOR_UNTRUSTED_CALLER = 0x00000001,
        INTERFACESAFE_FOR_UNTRUSTED_DATA = 0x00000002,
        INTERFACE_USES_DISPEX = 0x00000004,
        INTERFACE_USES_SECURITY_MANAGER = 0x00000008
    };

    //
    // MS IObjectSafety Interface definition
    //
    [
        ComImport(),
        Guid("CB5BDC81-93C1-11CF-8F20-00805F2CD064"),
        InterfaceType(ComInterfaceType.InterfaceIsIUnknown)
    ]
    public interface IObjectSafety
    {
        [PreserveSig]
        long GetInterfaceSafetyOptions(ref Guid iid, out int pdwSupportedOptions, out int pdwEnabledOptions);

        [PreserveSig]
        long SetInterfaceSafetyOptions(ref Guid iid, int dwOptionSetMask, int dwEnabledOptions);
    };

    [ProgId("ittru")]
    [ClassInterface(ClassInterfaceType.AutoDual), ComSourceInterfaces(typeof(ControlEvents))] //Implementing interface that will be visible from JS
    [Guid("D1FF97D1-06CA-4BB0-8704-62F30C131B55")]
    [ComVisible(true)]

    public class signAx : IObjectSafety
	{

        private ObjectSafetyOptions m_options =
           ObjectSafetyOptions.INTERFACESAFE_FOR_UNTRUSTED_CALLER |
           ObjectSafetyOptions.INTERFACESAFE_FOR_UNTRUSTED_DATA;

        #region [IObjectSafety implementation]
        public long GetInterfaceSafetyOptions(ref Guid iid, out int pdwSupportedOptions, out int pdwEnabledOptions)
        {
            pdwSupportedOptions = (int)m_options;
            pdwEnabledOptions = (int)m_options;
            return 0;
        }
        public long SetInterfaceSafetyOptions(ref Guid iid, int dwOptionSetMask, int dwEnabledOptions)
        {
            return 0;
        }
        #endregion


		private string myParam = "Empty";
        private X509Certificate2 certificate;

		public signAx()
		{
			
		}

         [ComVisible(true)]
        public string getCertificate(string title, string message, String subjectRegex, string issuerRegex)
        {
           
            try
            {
                String ret = "";
                X509Store store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
                store.Open(OpenFlags.OpenExistingOnly);
                X509Certificate2Collection certificates = store.Certificates;
                X509Certificate2Collection certificatesFiltered = new X509Certificate2Collection();
                X509Certificate2Enumerator enumCert = certificates.GetEnumerator();
                while(enumCert.MoveNext()){
                    X509Certificate2 certificateTmp = enumCert.Current;
                    bool subjectOk = true;
                    if (subjectRegex.Length > 0) {
                        Match matchSubject = Regex.Match(certificateTmp.Subject, subjectRegex,
                        RegexOptions.IgnoreCase);
                        subjectOk = matchSubject.Success;

                    }

                    bool issuerOk = true;
                    if (issuerRegex.Length > 0)
                    {
                        Match matchIssuer = Regex.Match(certificateTmp.Issuer, issuerRegex,
                            RegexOptions.IgnoreCase);
                        issuerOk = matchIssuer.Success;
                    }
                    if (subjectOk && issuerOk)
                    {
                        certificatesFiltered.Add(certificateTmp);
                    }


                }

                    if (certificatesFiltered.Count == 0)
                    {
                        return "";
                    }
                    else if (certificatesFiltered.Count == 1)
                    {
                        certificate = certificatesFiltered[0];
                    }
                    else
                    {
                        X509Certificate2Collection certificateSel = X509Certificate2UI.SelectFromCollection(certificatesFiltered, title, message, X509SelectionFlag.SingleSelection);
                        if (certificateSel.Count > 0)
                        {
                            certificate = certificateSel[0];
                        }
                    }
                    byte[] certAsByte = certificate.Export(X509ContentType.Cert);
                    string certAsString = Convert.ToBase64String(certAsByte);
                    ret = certAsString;
                    return ret;
            }
            catch (Exception e)
            {
                //ExceptionHandling.AppException(e);
                throw e;
            }
        }

        [ComVisible(true)]        
        public string sign(string hashAlg, string contentB64)
        {
            //return Convert.ToString(convertHashAlg(hashAlg));
            return sign(convertHashAlg(hashAlg), contentB64);
        }
         [ComVisible(true)]
        public string sign(int hashAlg, string contentB64)
        {
            byte[] content = Convert.FromBase64String(contentB64);
            return Convert.ToBase64String(sign(hashAlg, content));

        }
         [ComVisible(true)]
        public byte[] sign(string hashAlg, byte[] content)
        {
           return sign(convertHashAlg(hashAlg), content);
        }

         [ComVisible(true)]
        public int getKeySize()
        {
            RSACryptoServiceProvider publicKey
                                = certificate.PublicKey.Key as RSACryptoServiceProvider;
            return publicKey.KeySize;
        }
         [ComVisible(true)]
        public string getSubject()
        {
            return certificate.Subject;
        }

        static public byte[] SignMsg(int hashAlg,
                    byte[] msg,
                    X509Certificate2 signerCert)
        {
            //  Place message in a ContentInfo object.
            //  This is required to build a SignedCms object.
            ContentInfo contentInfo = new ContentInfo(msg);

            //  Instantiate SignedCms object with the ContentInfo above.
            //  Has default SubjectIdentifierType IssuerAndSerialNumber.
            //  Has default Detached property value false, so message is
            //  included in the encoded SignedCms.
            SignedCms signedCms = new SignedCms(contentInfo, true);

            //  Formulate a CmsSigner object, which has all the needed
            //  characteristics of the signer.

            CmsSigner cmsSigner = new CmsSigner(signerCert);

            //  Sign the PKCS #7 message.
            signedCms.ComputeSignature(cmsSigner, false);
            //  Encode the PKCS #7 message.
            return signedCms.Encode();
        }

 

        public byte[] sign(int hashAlg, byte[] content)
        {

            try
            {
                HashAlgorithm hash = null;
                byte[] signature = null;

                if (hashAlg == 99)
                {
                    signature = SignMsg(hashAlg, content, certificate);

                }
                else
                {

                    switch (hashAlg)
                    {
                        case 0:
                            hash = new SHA1Managed();
                            break;

                        case 1:
                            throw new Exception("unsupported algorithm");
                            break;

                        case 2:
                            hash = new SHA256Managed();
                            break;

                        case 3:
                            hash = new SHA384Managed();
                            break;

                        case 4:
                            hash = new SHA512Managed();
                            break;

                    }

                    RSACryptoServiceProvider privateKey
                             = certificate.PrivateKey as RSACryptoServiceProvider;
                    RSACryptoServiceProvider publicKey
                                = certificate.PublicKey.Key as RSACryptoServiceProvider;


                    bool verify = false;
                    signature = privateKey.SignData(content, hash);
                    verify = publicKey.VerifyData
                                            (content, hash, signature);
                  //  Array.Reverse(signature, 0, signature.Length);
                }
                return signature;
            }
            catch (Exception e)
            {
                //ExceptionHandling.AppException(e);
                throw e;
            }
        }

        static int convertHashAlg(String hashAlg)
        {
            String tmp = Regex.Replace(hashAlg, "[^0-9a-zA-Z]+", "");
            tmp = tmp.ToUpper();
            if (tmp.CompareTo("SHA1") == 0 || tmp.CompareTo("0") == 0)
            {
                return 0;
            }
            else if (tmp.CompareTo("SHA256") == 0 || tmp.CompareTo("2") == 0)
            {
                return 2;
            }
            else if (tmp.CompareTo("PKCS7") == 0 || tmp.CompareTo("99") == 0)
            {
                return 99;
            }
            throw new Exception("Hash alg not recognized: "+hashAlg);
        }

        //  Verify the encoded SignedCms message and return a Boolean
        //  value that specifies whether the verification was successful.
        //  Also return the original message that was signed, which is
        //  available as part of the SignedCms message after it
        //  is decoded.
        static public bool VerifyMsg(byte[] encodedSignedCms,
            out byte[] origMsg)
        {
            //  Prepare a SignedCms object in which to decode
            //  and verify.
            SignedCms signedCms = new SignedCms();

            signedCms.Decode(encodedSignedCms);

            //  Catch a verification exception in the event you want to
            //  advise the message recipient that security actions
            //  might be appropriate.
            try
            {
                //  Verify signature. Do not validate signer
                //  certificate for the purposes of this example.
                //  Note that in a production environment, validating
                //  the signer certificate chain will probably be
                //  necessary.
                Console.Write("Checking signature on message ... ");
                signedCms.CheckSignature(true);
                Console.WriteLine("Done.");
            }
            catch (System.Security.Cryptography.CryptographicException e)
            {
                Console.WriteLine("VerifyMsg caught exception:  {0}",
                    e.Message);
                Console.WriteLine("The message may have been modified " +
                    "in transit or storage. Authenticity of the " +
                    "message is not guaranteed.");
                origMsg = null;
                return false;
            }

            origMsg = signedCms.ContentInfo.Content;

            return true;
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
    [Guid("D1FF97D1-06CA-4BB0-8704-62F30C131B55")]
	[InterfaceType(ComInterfaceType.InterfaceIsIDispatch)]
	public interface ControlEvents
	{
		//Add a DispIdAttribute to any members in the source interface to specify the COM DispId.
		[DispId(0x60020001)]
		void OnClose(string redirectUrl); //This method will be visible from JS
	}


}
