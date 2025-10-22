import com.sun.net.httpserver.*;
import java.io.*;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;

public class Vulnerable {
    public static void main(String[] args) throws Exception {
        HttpServer srv = HttpServer.create(new InetSocketAddress(8100), 0);
        srv.createContext("/setcookie", exchange -> {
            String cookie = "sessionId=abc123";
            exchange.getResponseHeaders().add("Set-Cookie", cookie);
            String body = "Vulnerable: Set-Cookie header sent without Secure/HttpOnly\n";
            exchange.sendResponseHeaders(200, body.getBytes(StandardCharsets.UTF_8).length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(body.getBytes(StandardCharsets.UTF_8));
            }
        });
        srv.start();
        System.out.println("Vulnerable cookie server started on http://localhost:8100/setcookie");
    }
}
