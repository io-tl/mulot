# Fingerprint a Java stack

Confirm Java/Servlet and identify container/framework/version to choose targeted
tests. Gather signals with `browser_navigate`, `browser_get_cookies`,
`scan_passive` (its `headers` section), `http_flow` (response headers), `http_request`:

- **Cookies**: `JSESSIONID` ⇒ Java Servlet. `SESSION` (base64) ⇒ Spring Session.
  `XSRF-TOKEN` ⇒ Spring Security. `CASTGC` ⇒ CAS SSO. `oam*` ⇒ Oracle Access Mgr.
- **Headers** (`http_flow`): `Server: Apache-Coyote/1.1` or `.../Tomcat`,
  `Server: Jetty(x.y)`, `GlassFish`, `WildFly`/`JBoss`, `WebLogic`;
  `X-Powered-By: Servlet/x.y`, `X-Application-Context` (Spring Boot). Note cookie
  flags on `Set-Cookie`.
- **Paths/extensions**: `.jsp`, `.jspx`, `.do`/`.action` (Struts), `.faces`/`.xhtml`
  (JSF), `/seam/`, `;jsessionid=` in URLs (URL rewriting).
- **Bodies/errors**: Spring Boot **"Whitelabel Error Page"**, a Java stacktrace
  (`java.lang.NullPointerException`, `at org.springframework...`,
  `at org.apache.struts2...`, `com.mysql.jdbc`), `/error` JSON
  (`"trace":"java.lang..."`). Trigger one with a bad param, read via `http_flow_body`.
- **Spring Boot Actuator** — probe in ONE `http_fuzz` forced-browse
  (`url:"http://host/FUZZ"`, `match_status:200`; try both bare and `/actuator/`):
  `payloads:["actuator","actuator/env","actuator/health","actuator/heapdump",
  "actuator/mappings","actuator/beans","actuator/configprops","actuator/threaddump",
  "actuator/gateway/routes","actuator/loggers","env","heapdump","jolokia"]`. Any 200
  is a finding — exploit in skill: spring.
- **Classpath / gadget viability** (feeds skill: deserialization): grep any
  stacktrace, `/actuator/env`, or heapdump for library+version —
  `commons-collections` <3.2.2/<4.1, `commons-beanutils`, `groovy`,
  `jackson-databind` <2.9.x, `spring-core`. A vulnerable version present ⇒ a
  known gadget chain is viable; record it before attempting deserialization.
- **Forced-browse files/admin apps** (same pattern): `["WEB-INF/web.xml",
  "WEB-INF/classes/application.properties","manager/html","host-manager/html",
  "examples/servlets/","struts/webconsole.html","favicon.ico"]`. Tomcat `manager`
  with default creds = RCE via WAR upload.

Record: container + version, framework (Spring/Struts/JSF), Java version if leaked,
every exposed actuator/admin endpoint (each a finding), header version disclosure.

Evidence: the leaking header / stacktrace / actuator response.
Remediation: hide tokens (`server.tomcat...`, `server.error.include-stacktrace=never`),
disable manager/docs apps, restrict Actuator (`management.endpoints.web.exposure.include=health`).
