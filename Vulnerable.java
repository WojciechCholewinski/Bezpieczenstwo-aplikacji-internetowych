import java.nio.file.Files;
import java.nio.file.Path;

public class Vulnerable implements VulnerabilityLogic {
    @Override
    public String process(String userInput, EnvironmentContext context) throws Exception {
        // PODATNA IMPLEMENTACJA: brak walidacji ścieżki pliku
        Path safeDir = context.getSafeDirectory();

        // BŁĄD: Bezpośrednie użycie wejścia użytkownika do konstrukcji ścieżki
        Path requestedFile = safeDir.resolve(userInput);

        // Próba odczytu pliku bez sprawdzenia, czy jest w bezpiecznym katalogu
        if (Files.exists(requestedFile)) {
            byte[] content = Files.readAllBytes(requestedFile);
            return new String(content);
        } else {
            return "File not found";
        }
    }
}
