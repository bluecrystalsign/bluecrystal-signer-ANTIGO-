Imports System.Security.Cryptography
Imports System.IO

Public Class _Default
    Inherits Page

    Protected Sub Page_Load(ByVal sender As Object, ByVal e As EventArgs) Handles Me.Load

    End Sub

    Protected Sub Button1_Click(sender As Object, e As EventArgs) Handles Button1.Click

        Dim svc = New ittru_vb_WebApplication.ServiceReference1.Sign11SrvClient
        Dim uTime As Integer
        uTime = (DateTime.UtcNow - New DateTime(1970, 1, 1, 0, 0, 0)).TotalSeconds

        Dim saBuilder = New ittru_vb_WebApplication.ServiceReference1.saBuilderLegacy
        Dim hashCalc As HashAlgorithm

        Dim keyLength As Integer = Convert.ToInt32(Textbox1.Text)

        If keyLength < 2048 Then
            hashCalc = SHA1Managed.Create()
            saBuilder.alg = 0
            saBuilder.env = 4
        Else
            hashCalc = SHA256Managed.Create()
            saBuilder.alg = 2
            saBuilder.env = 0
        End If

        saBuilder.alg = 2
        saBuilder.certId = Textbox2.Text
        saBuilder.now = uTime
        Textbox5.Text = uTime


        Dim fInfo As FileInfo = New FileInfo("C:\Users\sergio\Dropbox\Homologaçoes do ITI\cartoes_RIC.pdf")
        Dim fileStream As FileStream = fInfo.Open(FileMode.Open)
        Dim hashValue() As Byte = hashCalc.ComputeHash(fileStream)
        Dim hashB64 As String = System.Convert.ToBase64String(hashValue)
        saBuilder.origHash = hashB64

        Textbox6.Text = hashB64
        saBuilder.process = False



        Dim cred As New ittru_vb_WebApplication.ServiceReference1.credential
        cred.userId = ""
        cred.secureInfo = ""


        Dim s1Ret = svc.createSA11(cred, saBuilder)
        Textbox4.Text = s1Ret
    End Sub

    Protected Sub Button2_Click(sender As Object, e As EventArgs) Handles Button2.Click
        Dim svc = New ittru_vb_WebApplication.ServiceReference1.Sign11SrvClient

        Dim cred As New ittru_vb_WebApplication.ServiceReference1.credential
        cred.userId = ""
        cred.secureInfo = ""

        Dim envBuilder As New ittru_vb_WebApplication.ServiceReference1.envelopeBuilder
        Dim ebResp As New ittru_vb_WebApplication.ServiceReference1.envelopeResp
        Dim keyLength As Integer = Convert.ToInt32(Textbox1.Text)

        Dim alg As Integer
        Dim env As Integer

        If keyLength < 2048 Then
            alg = 0
            env = 4
        Else
            alg = 2
            env = 0
        End If

        envBuilder.contentSize = -1
        envBuilder.shareId = 0
        envBuilder.signed = Textbox3.Text
        envBuilder.origHash = Textbox6.Text
        envBuilder.certId = Textbox2.Text
        envBuilder.now = Textbox5.Text


        Dim ebArr(0) As ittru_vb_WebApplication.ServiceReference1.envelopeBuilder
        ebArr(0) = envBuilder

        ebResp = svc.buildEnvelope11(cred, alg, env, ebArr)

        Textbox7.Text = ebResp.prefix

    End Sub
End Class