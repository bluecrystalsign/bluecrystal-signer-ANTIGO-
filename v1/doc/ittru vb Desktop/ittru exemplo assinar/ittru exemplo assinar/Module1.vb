Imports System.Security.Cryptography
Imports System.IO

Module Module1


    Sub Main()

        Dim txt As String = "assinatura digital usando ittru"
        Dim ittruAX As New ittru.signAx

        Dim certAsStr As String = ittruAX.getCertificate("titulo", "mensagem", "", "")
        Dim subjectAsStr As String = ittruAX.getSubject
        Dim keySizeAsInt As Integer = ittruAX.getKeySize

        Dim hashCalc As HashAlgorithm

        Dim fInfo As FileInfo = New FileInfo("C:\Users\sergio.fonseca\iniciativas\bluecrystal\vs13\ittru vb Desktop\ittru exemplo assinar\cartoes_RIC.pdf")
        Dim fileStream As FileStream = fInfo.Open(FileMode.Open)
        Dim ittruSaBuilder As New ittru_exemplo_assinar.ServiceReference1.saBuilderLegacy
        Dim ittruEnvBuilder As New ittru_exemplo_assinar.ServiceReference1.envelopeBuilder

        Console.WriteLine(txt)
        Console.Write("certificado: ")
        Console.WriteLine(certAsStr)
        ittruSaBuilder.certId = certAsStr
        ittruEnvBuilder.certId = certAsStr


        If keySizeAsInt < 2048 Then
            hashCalc = SHA1Managed.Create()
            ittruSaBuilder.alg = 0
            ittruSaBuilder.env = 4
        Else
            hashCalc = SHA256Managed.Create()
            ittruSaBuilder.alg = 2
            ittruSaBuilder.env = 0
        End If

        Dim hashValue() As Byte = hashCalc.ComputeHash(fileStream)
        Dim hashB64 As String = System.Convert.ToBase64String(hashValue)
        ittruSaBuilder.origHash = hashB64
        ittruEnvBuilder.origHash = hashB64

        Dim ittruSvc As New ittru_exemplo_assinar.ServiceReference1.Sign11SrvClient



        Dim uTime As Integer
        uTime = (DateTime.UtcNow - New DateTime(1970, 1, 1, 0, 0, 0)).TotalSeconds
        ittruSaBuilder.now = uTime
        ittruEnvBuilder.now = uTime
        ittruSaBuilder.process = False


        Dim cred As New ittru_exemplo_assinar.ServiceReference1.credential
        cred.userId = ""
        cred.secureInfo = ""

        Dim signSa As String = ittruSvc.createSA11(cred, ittruSaBuilder)

        Dim signRes As String
        If keySizeAsInt < 2048 Then
            signRes = ittruAX.sign(0, signSa)
        Else
            signRes = ittruAX.sign(2, signSa)
        End If



        ittruEnvBuilder.contentSize = -1
        ittruEnvBuilder.shareId = 0
        ittruEnvBuilder.signed = signRes

        Dim ebArr(0) As ittru_exemplo_assinar.ServiceReference1.envelopeBuilder
        ebArr(0) = ittruEnvBuilder

        Dim signEnvolpe As ittru_exemplo_assinar.ServiceReference1.envelopeResp = ittruSvc.buildEnvelope11(cred, ittruSaBuilder.alg, ittruSaBuilder.env, ebArr)



        Console.Write("assunto: ")
        Console.WriteLine(subjectAsStr)

        Console.Write("tam chave: ")
        Console.WriteLine(keySizeAsInt)

        Console.Write("valor do hash: ")
        Console.WriteLine(hashB64)

        Console.Write("atributos assinados: ")
        Console.WriteLine(signSa)

        Console.Write("assinatura: ")
        Console.WriteLine(signRes)

        Console.Write("resposta: ")
        Dim finalEnv As String = signEnvolpe.prefix

        Console.WriteLine(finalEnv)

        Console.ReadKey()
        Console.WriteLine("FIM")
    End Sub

End Module
