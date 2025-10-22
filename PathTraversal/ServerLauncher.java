import com.sun.net.httpserver.*;
import java.io.*;
import java.net.*;
import java.nio.file.*;

public class ServerLauncher {
    public static void main(String[] args) throws Exception {
        Path base = Paths.get(".").toAbsolutePath().normalize(); // katalog projektu
        Path publicDir = base.resolve("public").toAbsolutePath().normalize();

        // Utwórz kontekst: safeDir = publicDir
        EnvironmentContext ctx = new EnvironmentContext(publicDir, "student1");

        // Instancje implementacji
        VulnerabilityLogic vulnerable = new Vulnerable();
        VulnerabilityLogic secure = new SecureFileReader();

        // Server 1 - vulnerable on 8000
        startServer(8000, "/read", vulnerable, ctx, "VULNERABLE");

        // Server 2 - secure on 8001
        startServer(8001, "/read", secure, ctx, "SECURE");

        System.out.println("Servers started:");
        System.out.println("  Vulnerable -> http://localhost:8000/read?file=...");
        System.out.println("  Secure     -> http://localhost:8001/read?file=...");
    }

    private static void startServer(int port, String path, VulnerabilityLogic logic, EnvironmentContext ctx, String name) throws IOException {
        HttpServer server = HttpServer.create(new InetSocketAddress(port), 0);
        server.createContext(path, exchange -> {
    try {
        if (!"GET".equals(exchange.getRequestMethod())) {
            exchange.sendResponseHeaders(405, -1);
            return;
        }
        String query = exchange.getRequestURI().getQuery();
        String fileParam = null;
        if (query != null) {
            for (String part : query.split("&")) {
                if (part.startsWith("file=")) {
                    fileParam = java.net.URLDecoder.decode(part.substring(5), "UTF-8");
                }
            }
        }
        if (fileParam == null) {
            byte[] resp = "Missing file param\n".getBytes();
            exchange.sendResponseHeaders(400, resp.length);
            exchange.getResponseBody().write(resp);
            exchange.close();
            return;
        }

        String result = logic.process(fileParam, ctx);
        byte[] out = result.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        exchange.getResponseHeaders().add("Content-Type", "text/plain; charset=utf-8");
        exchange.sendResponseHeaders(200, out.length);
        exchange.getResponseBody().write(out);
        exchange.close();

    } catch (SecurityException se) {
        // → 403 Forbidden
        byte[] resp = ("Access denied").getBytes(java.nio.charset.StandardCharsets.UTF_8);
        exchange.getResponseHeaders().add("Content-Type", "text/plain; charset=utf-8");
        exchange.sendResponseHeaders(403, resp.length);
        exchange.getResponseBody().write(resp);
        exchange.close();

    } catch (Exception e) {
        // → 500 Internal Server Error
        byte[] resp = ("Error: " + e.getMessage()).getBytes(java.nio.charset.StandardCharsets.UTF_8);
        exchange.getResponseHeaders().add("Content-Type", "text/plain; charset=utf-8");
        exchange.sendResponseHeaders(500, resp.length);
        exchange.getResponseBody().write(resp);
        exchange.close();
    }
});

        server.setExecutor(java.util.concurrent.Executors.newCachedThreadPool());
        server.start();
        System.out.println(name + " server started on port " + port + " (safe dir = " + ctx.getSafeDirectory() + ")");
    }
}
