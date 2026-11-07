# Victim: a PINNED, pre-patch Apache Tomcat that is vulnerable to
#   CVE-2023-44487 (HTTP/2 Rapid Reset) and CVE-2025-8671 (MadeYouReset).
#
# Pinned on purpose. 10.1.43 is the last 10.1.x release BEFORE the fix
# (fixed in 10.1.44). This image is for an isolated, local-only lab only.
# Never expose it to an untrusted network.
FROM tomcat:10.1.43-jdk17-temurin

# Remove the default webapps and deploy our single "backend work" app as ROOT.
RUN rm -rf /usr/local/tomcat/webapps/*
COPY webapp/ /usr/local/tomcat/webapps/ROOT/

# Lab server config: h2c enabled, overhead protection disabled so the attack
# is reproducible. logging.properties turns on org.apache.coyote.http2 FINE
# logging, which is the Week-1 primary signal source for reset events.
COPY server.xml /usr/local/tomcat/conf/server.xml
COPY logging.properties /usr/local/tomcat/conf/logging.properties

# The exporter sidecar reads this log directory over a shared volume.
EXPOSE 8080
