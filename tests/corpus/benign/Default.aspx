<%@ Page Language="C#" AutoEventWireup="true" %>
<script runat="server">
    protected void Page_Load(object sender, EventArgs e)
    {
        Greeting.Text = "Hello from IIS at " + DateTime.Now.ToShortTimeString();
    }
</script>
<html><body><asp:Label ID="Greeting" runat="server" /></body></html>
