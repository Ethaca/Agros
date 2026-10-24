/**
 * Scripts run by `node -e` inside the trusted sidecar image (never inside the customer's image).
 *
 *   issuer  (run network, internal): serves the per-run public JWKS + OIDC/OAuth metadata on :8081. The same container
 *           is the relay the host forwarder `docker exec`s into to reach the app alias (so the app image needs no node).
 *   proxy   (build only; on the internal build network AND a per-run egress network): HTTP CONNECT proxy on :3128 that
 *           tunnels only to allowlisted hostnames on port 443. Everything else gets 403 and a "argos-proxy deny" log line.
 */

export const SIDECAR_READY = "argos-sidecar ready";
export const ISSUER_PORT = 8081;
export const PROXY_PORT = 3128;

export const issuerScript = (): string =>
  `const http=require("http");const iss=process.env.ARGOS_ISSUER;const jwks=process.env.ARGOS_JWKS;` +
  `const meta=JSON.stringify({issuer:iss,jwks_uri:iss+"/.well-known/jwks.json",id_token_signing_alg_values_supported:["RS256"],` +
  `subject_types_supported:["public"],response_types_supported:["code"]});` +
  `http.createServer((q,r)=>{const p=(q.url||"").split("?")[0];let b=null;` +
  `if(p==="/.well-known/jwks.json")b=jwks;else if(p==="/.well-known/openid-configuration"||p==="/.well-known/oauth-authorization-server")b=meta;` +
  `if(b===null){r.writeHead(404);r.end();return}r.writeHead(200,{"content-type":"application/json"});r.end(b)})` +
  `.listen(${ISSUER_PORT},()=>console.log(${JSON.stringify(SIDECAR_READY)}));`;

export const proxyScript = (): string =>
  `const http=require("http"),net=require("net");` +
  `const allow=new Set((process.env.ARGOS_PROXY_ALLOW||"").split(",").filter(Boolean));` +
  `const s=http.createServer((q,r)=>{console.log("argos-proxy deny plain-http "+String(q.url).slice(0,200));` +
  `r.writeHead(403);r.end("argos build proxy: only CONNECT to allowlisted hosts on 443\\n")});` +
  `s.on("connect",(q,c,head)=>{const u=String(q.url);const i=u.lastIndexOf(":");const h=u.slice(0,i).toLowerCase();const port=u.slice(i+1);` +
  `if(port!=="443"||!allow.has(h)){console.log("argos-proxy deny "+u.slice(0,200));c.end("HTTP/1.1 403 Forbidden\\r\\n\\r\\n");return}` +
  `const up=net.connect(443,h,()=>{c.write("HTTP/1.1 200 Connection Established\\r\\n\\r\\n");if(head&&head.length)up.write(head);up.pipe(c);c.pipe(up)});` +
  `up.on("error",e=>{console.log("argos-proxy upstream-error "+h+" "+e.code);c.destroy()});c.on("error",()=>up.destroy())});` +
  `s.listen(${PROXY_PORT},()=>console.log(${JSON.stringify(SIDECAR_READY)}));`;

/** Public dependency hosts the build may reach (exact names, port 443 only). */
export const MAVEN_HOSTS = ["repo.maven.apache.org", "repo1.maven.org", "repo.spring.io"];
export const GRADLE_HOSTS = [
  "services.gradle.org",
  "downloads.gradle.org",
  "plugins.gradle.org",
  "plugins-artifacts.gradle.org",
  // services.gradle.org redirects wrapper distributions to GitHub releases
  "github.com",
  "objects.githubusercontent.com",
  "release-assets.githubusercontent.com",
];
