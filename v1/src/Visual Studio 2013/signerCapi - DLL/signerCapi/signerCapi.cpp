#include "signerCapi.h"
#include <stdio.h>
#include <string.h>
#include < vcclr.h >
#include < stdlib.h >

#using <System.dll>
#using <System.Security.dll>

using namespace System;
using namespace System::Security::Cryptography;
using namespace System::Security::Cryptography::X509Certificates;
using namespace System::Security::Cryptography::Pkcs;
using namespace System::IO;
using namespace System::Text::RegularExpressions;

gcroot <X509Certificate2 ^>  certificate;

signerCapi::signerCapi(void)
{
}


signerCapi::~signerCapi(void)
{
}


extern "C"  __declspec(dllexport)  char* getCertificate(char* title,
	char* msg, char* subjectRegex, char* issuerRegex){
		try
            {
                char* ret = "";
				
                X509Store ^ store = gcnew X509Store(StoreName::My,StoreLocation::CurrentUser );
				store->Open( OpenFlags::ReadWrite );
				X509Certificate2Collection ^  certificates = store->Certificates;
                X509Certificate2Collection ^ certificatesFiltered = gcnew X509Certificate2Collection();
                X509Certificate2Enumerator ^ enumCert = certificates->GetEnumerator();
                while(enumCert->MoveNext()){
                    X509Certificate2 ^ certificateTmp = enumCert->Current;
                    bool subjectOk = true;

                    if (strlen(subjectRegex) > 0) {
                        subjectOk =  Regex::IsMatch(certificateTmp->Subject, Convert::ToString(subjectRegex),
                            RegexOptions::IgnoreCase );
                    }

                    bool issuerOk = true;
                    if (strlen(issuerRegex) > 0)
                    {
                        issuerOk =  Regex::IsMatch(certificateTmp->Issuer, Convert::ToString(issuerRegex),
                            RegexOptions::IgnoreCase );

                    }
                    if (subjectOk && issuerOk)
                    {
                        certificatesFiltered->Add(certificateTmp);
                    }


                }

                    if (certificatesFiltered->Count == 0)
                    {
                        return "";
                    }
                    else if (certificatesFiltered->Count == 1)
                    {
						certificate = certificatesFiltered[0];
                    }
                    else
                    {
                        X509Certificate2Collection ^ certificateSel = X509Certificate2UI::SelectFromCollection(certificatesFiltered, "title", "message", X509SelectionFlag::SingleSelection);
                        if (certificateSel->Count > 0)
                        {
                            certificate = certificateSel[0];
                        }
                    }
                    array <unsigned char, 1> ^ certAsByte = certificate->Export(System::Security::Cryptography::X509Certificates::X509ContentType::Cert);
                   String^ certAsString = Convert::ToBase64String(certAsByte, 
                                          0,
                                          certAsByte->Length);
                    pin_ptr<const wchar_t> wch = PtrToStringChars(certAsString);

					size_t convertedChars = 0;
					size_t  sizeInBytes = ((certAsString->Length + 1) * 2);
					errno_t err = 0;
					ret = (char *)malloc(sizeInBytes);

					err = wcstombs_s(&convertedChars, 
                    ret, sizeInBytes,
                    wch, sizeInBytes);
                    return ret;
            }
            catch (Exception ^ e)
            {
                //ExceptionHandling.AppException(e);
                throw e;
            }

}


extern "C"  __declspec(dllexport)  char* sign(int hashAlg, char* saValue){
	//return sign2(hashAlg, saValue);
	//return "";
//}
	
//char* signerCapi::sign2(int hashAlg, char* saValue){
			char* ret = "";
			try{
				String^ saStr = gcnew String(saValue);
				array <unsigned char, 1> ^ content = 
					Convert::FromBase64String(saStr);

				 if (hashAlg == 99)
                {
                   ContentInfo ^ contentInfo = gcnew ContentInfo(content);
				   SignedCms ^ signedCms = gcnew SignedCms(contentInfo, true);
				   CmsSigner ^ cmsSigner = gcnew CmsSigner(certificate);
				   signedCms->ComputeSignature(cmsSigner, false);
				   array <unsigned char, 1> ^  p7Encoded = signedCms->Encode();

				   String^ signAsString = Convert::ToBase64String(p7Encoded, 
                                          0,
                                          p7Encoded->Length);
						pin_ptr<const wchar_t> wch = PtrToStringChars(signAsString);

						size_t convertedChars = 0;
						size_t  sizeInBytes = ((signAsString->Length + 1) * 2);
						errno_t err = 0;
						ret = (char *)malloc(sizeInBytes);

						err = wcstombs_s(&convertedChars, 
						ret, sizeInBytes,
						wch, sizeInBytes);

						return ret;
                }
                else
                {
					HashAlgorithm ^ hash;

					switch (hashAlg)
					{
							case 0:
								hash = gcnew SHA1Managed();
								break;

							case 1:
								throw gcnew Exception("unsupported algorithm");
								break;

							case 2:
								hash = gcnew SHA256Managed();
								break;

							case 3:
								hash = gcnew SHA384Managed();
								break;

							case 4:
								hash = gcnew SHA512Managed();
								break;

					}
					AsymmetricAlgorithm ^ privateKey = certificate->PrivateKey;
					RSACryptoServiceProvider ^ privateCSP = (RSACryptoServiceProvider ^) privateKey;

					AsymmetricAlgorithm ^ publicKey  = certificate->PublicKey->Key;
					RSACryptoServiceProvider ^ publicCSP = (RSACryptoServiceProvider ^) publicKey;

					bool verify = false;
					
                    array <unsigned char, 1> ^ signature = privateCSP->SignData(content, hash);

					verify = publicCSP->VerifyData
                                            (content, hash, signature);
					if(verify){
						String^ signAsString = Convert::ToBase64String(signature, 
                                          0,
                                          signature->Length);
						pin_ptr<const wchar_t> wch = PtrToStringChars(signAsString);

						size_t convertedChars = 0;
						size_t  sizeInBytes = ((signAsString->Length + 1) * 2);
						errno_t err = 0;
						ret = (char *)malloc(sizeInBytes);

						err = wcstombs_s(&convertedChars, 
						ret, sizeInBytes,
						wch, sizeInBytes);
						return ret;
					} else {
						return "ERROR";
					}

				}
			}
	            catch (Exception ^ e)
            {

						pin_ptr<const wchar_t> wch = PtrToStringChars(e->Message);

						size_t convertedChars = 0;
						size_t  sizeInBytes = ((e->Message->Length + 1) * 2);
						errno_t err = 0;
						ret = (char *)malloc(sizeInBytes);

						err = wcstombs_s(&convertedChars, 
						ret, sizeInBytes,
						wch, sizeInBytes);
						return ret;

            }
				return "";
}


extern "C"  __declspec(dllexport)  int getKeySize(){
	AsymmetricAlgorithm ^ publicKey  = certificate->PublicKey->Key;
	return publicKey->KeySize;
}

extern "C"  __declspec(dllexport)  char* getSubject(void){


        pin_ptr<const wchar_t> wch = PtrToStringChars(certificate->Subject);

		size_t convertedChars = 0;
		size_t  sizeInBytes = ((certificate->Subject->Length + 1) * 2);
		errno_t err = 0;
		char * ret = (char *)malloc(sizeInBytes);

		err = wcstombs_s(&convertedChars, 
        ret, sizeInBytes,
        wch, sizeInBytes);
	
		return ret;
}

