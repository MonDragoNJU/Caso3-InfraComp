import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.util.ArrayList;
import java.util.Map;
import java.util.Random;

import javax.crypto.SecretKey;

import java.io.FileInputStream;
import java.io.ObjectInputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.Socket;

public class Cliente {

    private static String host = "localhost";
    private static int puerto = 12345;
    private static PublicKey llavePublica;
    private static String ip = generarIP();

    public Cliente() {
        System.out.println("CLIENTE - Mi IP es: " + ip);
        leerLlave();
    }

    private void leerLlave() {
        try (FileInputStream archivoTexto = new FileInputStream("llaves/servidor_llave_publica.txt");
             ObjectInputStream oisTexto = new ObjectInputStream(archivoTexto)) {
            llavePublica = (PublicKey) oisTexto.readObject();
        } catch (IOException | ClassNotFoundException e) {
            System.out.println("Error al leer la llave pública: " + e.getMessage());
        }
    }

    private void iniciarCliente() throws Exception {
        try (Socket socketCliente = new Socket(host, puerto)) {
            ObjectOutputStream out = new ObjectOutputStream(socketCliente.getOutputStream());
            ObjectInputStream in = new ObjectInputStream(socketCliente.getInputStream());

            // Enviar HELLO al servidor
            out.writeObject("HELLO");
            System.out.println("CLIENTE - HELLO.");
            out.flush();

            //Crear reto y enviarlo al servidor
            byte[] reto = Utilidades.generarReto(16); 
            out.writeObject(reto);
            out.flush();

            System.out.println("CLIENTE - Reto enviado al servidor.");

            // Recibir reto del servidor
            byte[] retoCifrado = (byte[]) in.readObject();
            byte[] retoDescifrado = Utilidades.descifrarRSA(retoCifrado, llavePublica);

            if (!java.util.Arrays.equals(reto, retoDescifrado)) {
                System.out.println("CLIENTE - Error de autenticación: el reto no coincide.");
                out.writeObject("ERROR");
                out.flush();
            }

            // Enviar respuesta al servidor
            out.writeObject("OK");
            out.flush();

            System.out.println("CLIENTE - Respuesta enviada al servidor.");

            //Diffie-Hellman
            //Recibir G, P, G^X, F(K_w-, (G, P, G^x)) del servidor
            BigInteger g = (BigInteger) in.readObject();
            BigInteger p = (BigInteger) in.readObject();
            BigInteger gX = (BigInteger) in.readObject();
            byte[] firma = (byte[]) in.readObject();

            //Verificar firma del servidor
            Signature sigVerif = Signature.getInstance("SHA256withRSA");
            sigVerif.initVerify(llavePublica);
            sigVerif.update(g.toByteArray());
            sigVerif.update(p.toByteArray());
            sigVerif.update(gX.toByteArray());
            boolean esValida = sigVerif.verify(firma);

            if (esValida) {
                System.out.println("CLIENTE - Firma válida. Autenticación exitosa.");
                out.writeObject("OK");
                out.flush();
            } else {
                System.out.println("CLIENTE - Firma inválida. Autenticación fallida.");
                out.writeObject("ERROR");
                out.flush();
                return;
            }

            //Generar G^y
            SecureRandom random = new SecureRandom();
            BigInteger y = new BigInteger(1024 - 1, random);

            BigInteger gY = g.modPow(y, p);

            //Calcular (G^x)^y mod p
            BigInteger gXy = gX.modPow(y, p);
            byte[] secreto = Utilidades.intToBytes(gXy.intValue());

            //Generar llave simetrica para cifrar K_AB1
            
            SecretKey llaveAES = Utilidades.derivarLlaves(secreto)[0];

            //Generar llave simetrica para MAC K_AB2

            SecretKey llaveHMAC = Utilidades.derivarLlaves(secreto)[1];

            //Enviar G^y al servidor
            out.writeObject(gY);
            out.flush();

            System.out.println("CLIENTE - G^Y enviado al servidor.");

            //Enviar vector de inicializacion al servidor
            byte[] iv = new byte[16];
            random.nextBytes(iv);
            out.writeObject(iv);
            out.flush();

            System.out.println("CLIENTE - IV enviado al servidor.");

            //Recibir tabla de ids de servicios del servidor
            byte[] tablaIdsServiciosCifrados = (byte[]) in.readObject();
            
            //Verificar HMAC de la tabla de ids de servicios del servidor
            byte[] hmacTablaIdsServiciosRecibido = (byte[]) in.readObject();
            byte[] hmacTablaIdsServiciosCalculado = Utilidades.hmac(tablaIdsServiciosCifrados, llaveHMAC);

            if (!java.util.Arrays.equals(hmacTablaIdsServiciosRecibido, hmacTablaIdsServiciosCalculado)) {
                System.out.println("CLIENTE - Error de autenticación: HMAC de la tabla de ids de servicios no coincide.");
                return;
            }

            //Desencriptar tabla de ids de servicios
            byte[] tablaIdsServiciosDesencriptadal = Utilidades.descifrarAES(tablaIdsServiciosCifrados, llaveAES, iv);
            @SuppressWarnings("unchecked")
            Map<Integer, String> tablaIdsServicios = (Map<Integer, String>) Utilidades.deserializar(tablaIdsServiciosDesencriptadal);

            //Elegir un id de servicio al azar
            ArrayList<Integer> idsServicios = new ArrayList<>(tablaIdsServicios.keySet());
            int idServicioElegido = idsServicios.get(random.nextInt(idsServicios.size()));

            //Enviar id + IP de servicio al servidor
            String eleccionId = idServicioElegido + ";" + ip;
            
            //Cifrar la eleccionId con la llave AES
            byte[] eleccionIdCifrado = Utilidades.cifrarAES(eleccionId.getBytes(), llaveAES, iv);

            //Calcular HMAC de la eleccionIdCifrado
            byte[] hmacEleccionId = Utilidades.hmac(eleccionIdCifrado, llaveHMAC);

            //Enviar eleccionIdCifrado al servidor
            out.writeObject(eleccionIdCifrado);
            out.flush();

            //Enviar HMAC de la eleccionIdCifrado al servidor
            out.writeObject(hmacEleccionId);
            out.flush();

            //Recibir IP y puerto del servicio
            byte[] infoServidorCifrado = (byte[]) in.readObject();
            byte[] hmacInfoServidorRecibido = (byte[]) in.readObject();

            byte[] hmacInfoServidorCalculado = Utilidades.hmac(infoServidorCifrado, llaveHMAC);
            if (!java.util.Arrays.equals(hmacInfoServidorRecibido, hmacInfoServidorCalculado)) {
                System.out.println("CLIENTE - Error de autenticación: HMAC de la IP y puerto del servicio no coincide.");
                return;
            }

            //Desencriptar IP y puerto del servicio
            byte[] infoServidorDesencriptado = Utilidades.descifrarAES(infoServidorCifrado, llaveAES, iv);
            String infoServidor = new String(infoServidorDesencriptado, "UTF-8");
            String[] partes = infoServidor.split(";");
            String ipServidor = partes[1];
            String puertoServidor = partes[2];

            System.out.println("CLIENTE - IP del servicio: " + ipServidor + ", Puerto: " + puertoServidor);

            // Finalizar protocolo
            out.writeObject("OK");
            out.flush();
            System.out.println("CLIENTE - Protocolo finalizado.");

            

        } catch (Exception e) {
            System.out.println("Error al iniciar el cliente: " + e.getMessage());
        }
    }

    public static String generarIP() {
        Random rand = new Random();
        return rand.nextInt(256) + "." +
               rand.nextInt(256) + "." +
               rand.nextInt(256) + "." +
               rand.nextInt(256);
    }

    public static void main(String[] args) throws Exception {
        new Cliente().iniciarCliente();
    }
}
