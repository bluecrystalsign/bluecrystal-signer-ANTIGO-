<%@ Page Title="Home Page" Language="VB" MasterPageFile="~/Site.Master" AutoEventWireup="true" CodeBehind="Default.aspx.vb" Inherits="ittru_vb_WebApplication._Default" %>

<asp:Content ID="BodyContent" ContentPlaceHolderID="MainContent" runat="server">

   <div>
       <asp:Button ID="Button1" runat="server" Text="Passo 2" />
       <br />
       <br />
       <asp:Button ID="Button2" runat="server" Text="Passo 4" />
        <p>
            <br/>
            <asp:Label ID="Label2" runat="server" Text="Tamanho:">  </asp:Label>    <asp:TextBox ID="Textbox1" runat="server"></asp:TextBox><br />
            <asp:Label ID="Label4" runat="server" Text="Assunto:">  </asp:Label>    <asp:Label ID="Label5" runat="server"></asp:Label><br />
            <asp:Label ID="Label6" runat="server" Text="Cert:">     </asp:Label>    <asp:TextBox ID="Textbox2" runat="server"></asp:TextBox><br />

            <asp:Label ID="Label8" runat="server" Text="Time:">     </asp:Label>   <asp:TextBox ID="Textbox5" runat="server"></asp:TextBox><br />
            <asp:Label ID="Label14" runat="server" Text="Hash:">    </asp:Label>   <asp:TextBox ID="Textbox6" runat="server"></asp:TextBox><br />


            <asp:Label ID="Label7" runat="server" Text="SignAttr:">     </asp:Label>    <asp:TextBox ID="Textbox4" runat="server"></asp:TextBox><br />
            <asp:Label ID="Label3" runat="server" Text="Assinatura:">     </asp:Label>    <asp:TextBox ID="Textbox3" runat="server"></asp:TextBox><br />

            <asp:Label ID="Label9" runat="server" Text="Envelope:">     </asp:Label>    <asp:TextBox ID="Textbox7" runat="server"></asp:TextBox><br />


        </p>
    </div>

</asp:Content>
