import java.io.FileWriter;
import java.io.IOException;

public class MedidorTiempos {

    private static final String ARCHIVO = "resultados.csv";
    private static boolean cabeceraEscrita = false;

    public static synchronized void escribirTiempo(String escenario, String tipoOperacion, double tiempo) {
        try (FileWriter writer = new FileWriter(ARCHIVO, true)) {
            if (!cabeceraEscrita) {
                writer.write("Escenario,TipoOperacion,Tiempo(ms)\n");
                cabeceraEscrita = true;
            }
            writer.write(escenario + "," + tipoOperacion + "," + tiempo + "\n");
        } catch (IOException e) {
            System.out.println("Error escribiendo CSV: " + e.getMessage());
        }
    }
}
