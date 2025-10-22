import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.io.IOException;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.concurrent.ConcurrentHashMap;
import java.time.Instant;

public class SecureFileReader implements VulnerabilityLogic {
    
    // Stałe bezpieczeństwa
    private static final long MAX_FILE_SIZE = 10 * 1024 * 1024; // 10 MB
    private static final int MAX_PATH_LENGTH = 255;
    private static final int MAX_FILENAME_LENGTH = 100;
    private static final Pattern SAFE_FILENAME_PATTERN = Pattern.compile("^[a-zA-Z0-9._-]+$");
    private static final Set<String> ALLOWED_EXTENSIONS = Set.of(
        ".txt", ".log", ".csv", ".json", ".xml", ".properties", ".conf"
    );
    
    // Rate limiting
    private static final int MAX_REQUESTS_PER_MINUTE = 100;
    private final RateLimiter rateLimiter = new RateLimiter(MAX_REQUESTS_PER_MINUTE);
    
    // Cache dla sprawdzonych ścieżek (opcjonalne)
    private final ConcurrentHashMap<String, CachedFile> fileCache = new ConcurrentHashMap<>();
    
    @Override
    public String process(String userInput, EnvironmentContext context) throws Exception {
        try {
            // 1. Walidacja podstawowa
            validateInput(userInput);
            
            // 2. Rate limiting
            if (!rateLimiter.allowRequest(context.getUserId())) {
                throw new SecurityException("Too many requests");
            }
            
            // 3. Pobierz bezpieczny katalog z pełną walidacją
            Path safeDir = validateAndGetSafeDirectory(context);
            
            // 4. Bezpieczna konstrukcja ścieżki
            Path requestedFile = securelyResolvePath(safeDir, userInput);
            
            // 5. Wielopoziomowa weryfikacja bezpieczeństwa
            SecurityCheckResult securityCheck = performSecurityChecks(requestedFile, safeDir);
           if (!securityCheck.isAllowed()) {
                logSecurityViolation(userInput, context, securityCheck.getReason());
                throw new SecurityException("Access denied: " + securityCheck.getReason());
            }
            
            // 6. Sprawdź cache (opcjonalne)
            String cachedContent = getCachedContent(requestedFile);
            if (cachedContent != null) {
                return cachedContent;
            }
            
            // 7. Bezpieczne odczytanie pliku
            String content = securelyReadFile(requestedFile);
            
            // 8. Dodaj do cache
            cacheFile(requestedFile, content);
            
            return content;
            
        } catch (SecurityException e) {
            logSecurityException(e, userInput, context);
            throw e;
        } catch (IOException e) {
            // Nie ujawniaj szczegółów błędu
            return "File operation failed";
        } catch (Exception e) {
            logError(e);
            return "An error occurred";
        }
    }
    
    private void validateInput(String userInput) {
        // Null check
        if (userInput == null || userInput.trim().isEmpty()) {
            throw new IllegalArgumentException("Invalid input");
        }
        
        // Długość
        if (userInput.length() > MAX_PATH_LENGTH) {
            throw new IllegalArgumentException("Path too long");
        }
        
        // Niebezpieczne znaki i sekwencje
        String[] dangerousPatterns = {
            "..", "~", "%", "\\", ":", "*", "?", "\"", "<", ">", "|",
            "\0", "\n", "\r", "../", "..\\", "/..", "\\..",
            "%2e%2e", "%252e", "..;", "..%00", "..%01"
        };
        
        String normalizedInput = userInput.toLowerCase();
        for (String pattern : dangerousPatterns) {
            if (normalizedInput.contains(pattern)) {
                throw new SecurityException("Dangerous pattern detected: " + pattern);
            }
        }
        
        // Sprawdź URLencoded warianty
        if (containsUrlEncodedTraversal(userInput)) {
            throw new SecurityException("URL encoded traversal detected");
        }
    }
    
    private boolean containsUrlEncodedTraversal(String input) {
        String[] encodedPatterns = {
            "%2e%2e%2f", "%2e%2e/", "..%2f", "%2e%2e%5c",
            "%252e%252e%255c", "%252e%252e%252f"
        };
        
        String lower = input.toLowerCase();
        for (String pattern : encodedPatterns) {
            if (lower.contains(pattern)) {
                return true;
            }
        }
        return false;
    }
    
    private Path validateAndGetSafeDirectory(EnvironmentContext context) throws IOException {
        Path safeDir = context.getSafeDirectory();
        
        if (safeDir == null) {
            throw new SecurityException("Safe directory not configured");
        }
        
        // Upewnij się, że katalog istnieje i jest katalogiem
        if (!Files.exists(safeDir) || !Files.isDirectory(safeDir)) {
            throw new SecurityException("Invalid safe directory");
        }
        
        // Pobierz kanoniczną ścieżkę
        return safeDir.toRealPath();
    }
    
    private Path securelyResolvePath(Path safeDir, String userInput) throws IOException {
        // KLUCZOWE: Wieloetapowa normalizacja
        
        // 1. Usuń leading/trailing slashes i spacje
        String cleaned = userInput.trim().replaceAll("^[/\\\\]+", "").replaceAll("[/\\\\]+$", "");
        
        // 2. Zamień backslashe na forward slashe
        cleaned = cleaned.replace('\\', '/');
        
        // 3. Usuń wielokrotne slashe
        cleaned = cleaned.replaceAll("/+", "/");
        
        // 4. Waliduj nazwę pliku
        String filename = Paths.get(cleaned).getFileName().toString();
        if (!isValidFilename(filename)) {
            throw new SecurityException("Invalid filename");
        }
        
        // 5. Rozwiąż ścieżkę z wieloma zabezpieczeniami
        Path resolved = safeDir.resolve(cleaned).normalize();
        
        // 6. Pobierz rzeczywistą ścieżkę (rozwiązuje symlinki)
        if (Files.exists(resolved)) {
            resolved = resolved.toRealPath();
        } else {
            // Jeśli plik nie istnieje, sprawdź rodzica
            Path parent = resolved.getParent();
            if (parent != null && Files.exists(parent)) {
                parent = parent.toRealPath();
                resolved = parent.resolve(resolved.getFileName());
            }
        }
        
        return resolved;
    }
    
    private boolean isValidFilename(String filename) {
        if (filename.length() > MAX_FILENAME_LENGTH) {
            return false;
        }
        
        // Sprawdź wzorzec
        if (!SAFE_FILENAME_PATTERN.matcher(filename).matches()) {
            return false;
        }
        
        // Sprawdź rozszerzenie
        String extension = getFileExtension(filename);
        if (!ALLOWED_EXTENSIONS.contains(extension.toLowerCase())) {
            return false;
        }
        
        return true;
    }
    
    private String getFileExtension(String filename) {
        int lastDot = filename.lastIndexOf('.');
        if (lastDot > 0 && lastDot < filename.length() - 1) {
            return filename.substring(lastDot);
        }
        return "";
    }
    
    private SecurityCheckResult performSecurityChecks(Path requestedFile, Path safeDir) throws IOException {
        // 1. Sprawdź czy ścieżka jest w bezpiecznym katalogu
        if (!requestedFile.startsWith(safeDir)) {
            return new SecurityCheckResult(false, "Path outside safe directory");
        }
        
        // 2. Sprawdź czy to nie jest symlink prowadzący poza katalog
        if (Files.isSymbolicLink(requestedFile)) {
            Path target = Files.readSymbolicLink(requestedFile);
            if (!target.normalize().startsWith(safeDir)) {
                return new SecurityCheckResult(false, "Symlink points outside safe directory");
            }
        }
        
        // 3. Sprawdź czy plik istnieje
        if (!Files.exists(requestedFile)) {
            return new SecurityCheckResult(false, "File does not exist");
        }
        
        // 4. Sprawdź czy to jest zwykły plik (nie katalog, device, etc.)
        if (!Files.isRegularFile(requestedFile)) {
            return new SecurityCheckResult(false, "Not a regular file");
        }
        
        // 5. Sprawdź uprawnienia
        if (!Files.isReadable(requestedFile)) {
            return new SecurityCheckResult(false, "File is not readable");
        }
        
        // 6. Sprawdź rozmiar pliku
        long fileSize = Files.size(requestedFile);
        if (fileSize > MAX_FILE_SIZE) {
            return new SecurityCheckResult(false, "File too large: " + fileSize);
        }
        
        // 7. Sprawdź typ MIME (opcjonalne)
        String mimeType = Files.probeContentType(requestedFile);
        if (mimeType != null && !isAllowedMimeType(mimeType)) {
            return new SecurityCheckResult(false, "Forbidden MIME type: " + mimeType);
        }
        
        return new SecurityCheckResult(true, "All checks passed");
    }
    
    private boolean isAllowedMimeType(String mimeType) {
        Set<String> allowedMimeTypes = Set.of(
            "text/plain", "text/csv", "application/json", 
            "application/xml", "text/xml"
        );
        return allowedMimeTypes.contains(mimeType);
    }
    
    private String securelyReadFile(Path file) throws IOException {
        // Użyj try-with-resources dla automatycznego zamknięcia
        byte[] content = Files.readAllBytes(file);
        
        // Walidacja zawartości
        if (!isValidContent(content)) {
            throw new SecurityException("Invalid file content");
        }
        
        return new String(content, StandardCharsets.UTF_8);
    }
    
    private boolean isValidContent(byte[] content) {
        // Sprawdź czy nie zawiera binarnych danych
        for (byte b : content) {
            if (b == 0) {
                return false; // Null byte - prawdopodobnie plik binarny
            }
        }
        return true;
    }
    
    // Klasy pomocnicze
    private static class SecurityCheckResult {
        private final boolean allowed;
        private final String reason;
        
        public SecurityCheckResult(boolean allowed, String reason) {
            this.allowed = allowed;
            this.reason = reason;
        }
        
        public boolean isAllowed() { return allowed; }
        public String getReason() { return reason; }
    }
    
    private static class RateLimiter {
        private final int maxRequests;
        private final ConcurrentHashMap<String, RequestCounter> counters = new ConcurrentHashMap<>();
        
        public RateLimiter(int maxRequests) {
            this.maxRequests = maxRequests;
        }
        
        public boolean allowRequest(String userId) {
            RequestCounter counter = counters.compute(userId, (k, v) -> {
                if (v == null || v.isExpired()) {
                    return new RequestCounter();
                }
                v.increment();
                return v;
            });
            return counter.getCount() <= maxRequests;
        }
    }
    
    private static class RequestCounter {
        private int count = 1;
        private final long windowStart = System.currentTimeMillis();
        private static final long WINDOW_SIZE = 60_000; // 1 minuta
        
        public void increment() { count++; }
        public int getCount() { return count; }
        public boolean isExpired() {
            return System.currentTimeMillis() - windowStart > WINDOW_SIZE;
        }
    }
    
    private static class CachedFile {
        private final String content;
        private final Instant cachedAt;
        private static final long CACHE_TTL_SECONDS = 300; // 5 minut
        
        public CachedFile(String content) {
            this.content = content;
            this.cachedAt = Instant.now();
        }
        
        public boolean isValid() {
            return Instant.now().isBefore(cachedAt.plusSeconds(CACHE_TTL_SECONDS));
        }
        
        public String getContent() { return content; }
    }
    
    // Metody pomocnicze
    private String getCachedContent(Path file) {
        String key = file.toString();
        CachedFile cached = fileCache.get(key);
        if (cached != null && cached.isValid()) {
            return cached.getContent();
        }
        fileCache.remove(key);
        return null;
    }
    
    private void cacheFile(Path file, String content) {
        fileCache.put(file.toString(), new CachedFile(content));
    }
    
    private void logSecurityViolation(String input, EnvironmentContext context, String reason) {
        // Loguj próby naruszenia bezpieczeństwa
        System.err.printf("SECURITY: Path traversal attempt - User: %s, Input: %s, Reason: %s%n",
            context.getUserId(), input, reason);
    }
    
    private void logSecurityException(Exception e, String input, EnvironmentContext context) {
        System.err.printf("SECURITY EXCEPTION: User: %s, Input: %s, Error: %s%n",
            context.getUserId(), input, e.getMessage());
    }
    
    private void logError(Exception e) {
        System.err.println("ERROR: " + e.getClass().getName());
    }
}