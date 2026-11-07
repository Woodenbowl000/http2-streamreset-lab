<%@ page contentType="text/plain" %><%
  // Simulated backend work endpoint for the lab.
  // Query param ?ms=NNN controls how long the "request" occupies a worker,
  // standing in for real backend processing. Default is a short delay so the
  // divergence between protocol-layer streams and app-layer work is visible.
  String msParam = request.getParameter("ms");
  long ms = 200;
  try { if (msParam != null) ms = Math.max(0, Math.min(10000, Long.parseLong(msParam))); } catch (Exception e) {}
  long start = System.currentTimeMillis();
  try { Thread.sleep(ms); } catch (InterruptedException ie) { Thread.currentThread().interrupt(); }
%>ok worked_ms=<%= (System.currentTimeMillis()-start) %> thread=<%= Thread.currentThread().getName() %>
