import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * Spring-less stand-in for a JVM target (test/jvm-stack.test.ts): boots on SERVER_PORT and reports, from inside the
 * sandbox, what it can reach. No dependencies: compiled by `javac` in the build container, run on a JRE.
 */
public class Server {
    public static void main(String[] args) throws Exception {
        if (System.getenv("CRASH") != null) {
            System.out.println("boot failed: CRASH set, db password was " + System.getenv("SPRING_DATASOURCE_PASSWORD"));
            System.exit(3);
        }
        int port = Integer.parseInt(System.getenv("SERVER_PORT"));
        HttpServer s = HttpServer.create(new InetSocketAddress(port), 0);
        s.createContext("/health", x -> reply(x, 200, "{\"ok\":true}"));
        s.createContext("/secured", x -> reply(x, 401, "{}"));
        s.createContext("/probe", x -> reply(x, 200, probe()));
        s.start();
        System.out.println("probe up on " + port);
    }

    static void reply(HttpExchange x, int status, String body) throws java.io.IOException {
        byte[] b = body.getBytes(StandardCharsets.UTF_8);
        x.getResponseHeaders().set("content-type", "application/json");
        x.sendResponseHeaders(status, b.length);
        x.getResponseBody().write(b);
        x.close();
    }

    interface Check { String run() throws Exception; }

    static String attempt(Check c) {
        try {
            return "ok:" + c.run();
        } catch (Exception e) {
            return "error:" + e.getClass().getSimpleName() + ":" + e.getMessage();
        }
    }

    static String tcp(String host, int port) throws Exception {
        try (Socket so = new Socket()) {
            so.connect(new InetSocketAddress(host, port), 3000);
            return "connected";
        }
    }

    static String probe() {
        Map<String, String> r = new TreeMap<>();
        r.put("jwks", attempt(() -> {
            HttpResponse<String> res = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(3)).build().send(
                HttpRequest.newBuilder(URI.create(System.getenv("SPRING_SECURITY_OAUTH2_RESOURCESERVER_JWT_JWK_SET_URI"))).build(),
                HttpResponse.BodyHandlers.ofString());
            return res.statusCode() + " " + res.body();
        }));
        r.put("oidc", attempt(() -> {
            HttpResponse<String> res = HttpClient.newHttpClient().send(
                HttpRequest.newBuilder(URI.create(System.getenv("SPRING_SECURITY_OAUTH2_RESOURCESERVER_JWT_ISSUER_URI") + "/.well-known/openid-configuration")).build(),
                HttpResponse.BodyHandlers.ofString());
            return res.statusCode() + " " + res.body();
        }));
        r.put("db", attempt(() -> tcp("argos-db", 5432)));
        r.put("egressIp", attempt(() -> tcp("1.1.1.1", 443)));
        r.put("egressDns", attempt(() -> InetAddress.getByName("example.com").getHostAddress()));
        r.put("hostDns", attempt(() -> tcp("host.docker.internal", 22)));
        r.put("writeRoot", attempt(() -> Files.writeString(Path.of("/argos-probe.txt"), "x").toString()));
        r.put("writeTmp", attempt(() -> Files.writeString(Path.of("/tmp/argos-probe.txt"), "x").toString()));
        r.put("dockerSock", String.valueOf(Files.exists(Path.of("/var/run/docker.sock"))));
        r.put("status", attempt(() -> String.join("|", Files.readAllLines(Path.of("/proc/self/status")).stream()
            .filter(l -> l.startsWith("Uid:") || l.startsWith("CapEff:") || l.startsWith("NoNewPrivs:")).toList())));
        r.put("egressFile", attempt(() -> Files.readString(Path.of("out/egress.txt"))));
        List<String> env = new ArrayList<>(System.getenv().keySet());
        env.sort(null);
        r.put("envNames", String.join(",", env));
        r.put("custom", String.valueOf(System.getenv("CUSTOM")));
        StringBuilder sb = new StringBuilder("{");
        for (Map.Entry<String, String> e : r.entrySet()) {
            if (sb.length() > 1) sb.append(',');
            sb.append(q(e.getKey())).append(':').append(q(e.getValue()));
        }
        return sb.append('}').toString();
    }

    static String q(String s) {
        StringBuilder b = new StringBuilder("\"");
        for (char c : s.toCharArray()) {
            if (c == '"' || c == '\\') b.append('\\').append(c);
            else if (c < 0x20) b.append(String.format("\\u%04x", (int) c));
            else b.append(c);
        }
        return b.append('"').toString();
    }
}
