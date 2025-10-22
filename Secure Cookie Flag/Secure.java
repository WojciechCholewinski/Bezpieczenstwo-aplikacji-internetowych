import com.sun.net.httpserver.*;
import java.io.*;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;

public class Secure {
    public static void main(String[] args) throws Exception {
        HttpServer srv = HttpServer.create(new InetSocketAddress(8101), 0);
        srv.createContext("/setcookie", exchange -> {
            String cookie = "sessionId=abc123; Secure; HttpOnly; SameSite=Strict";
            exchange.getResponseHeaders().add("Set-Cookie", cookie);
            String body = "Secure: Set-Cookie header sent with Secure; HttpOnly; SameSite=Strict\n";
            exchange.sendResponseHeaders(200, body.getBytes(StandardCharsets.UTF_8).length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(body.getBytes(StandardCharsets.UTF_8));
            }
        });
        srv.start();
        System.out.println("Secure cookie server started on http://localhost:8101/setcookie");
    }
}
