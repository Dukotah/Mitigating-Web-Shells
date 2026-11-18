<%@ page contentType="text/html; charset=UTF-8" %>
<% String who = request.getParameter("who"); %>
<html><body>Hello <%= who == null ? "world" : org.owasp.encoder.Encode.forHtml(who) %></body></html>
