import java.io.*;
import java.math.BigInteger;
import java.net.Socket;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.util.*;

import javax.crypto.SecretKey;

public class Cliente extends Thread {

    private static final String HOST = "localhost";
    private static final int PUERTO = 12345;
    private static final String RUTA_LLAVE_PUBLICA = "llaves/servidor_llave_publica.txt";

    private PublicKey llavePublica;
    private static final String ip = generarIP();

    public Cliente() {
        System.out.println("CLIENTE - Mi IP es: " + ip);
        leerLlavePublica();
    }

    private void leerLlavePublica() {
        try (FileInputStream archivo = new FileInputStream(RUTA_LLAVE_PUBLICA);
             ObjectInputStream ois = new ObjectInputStream(archivo)) {
            llavePublica = (PublicKey) ois.readObject();
        } catch (IOException | ClassNotFoundException e) {
            System.out.println("Error al leer la llave pública: " + e.getMessage());
        }
    }

    public void iniciarCliente() {
        try (Socket socket = new Socket(HOST, PUERTO);
             ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
             ObjectInputStream in = new ObjectInputStream(socket.getInputStream())) {

            out.writeObject("HELLO");
            out.flush();
            System.out.println("CLIENTE - HELLO.");

            byte[] reto = Utilidades.generarReto(16);
            out.writeObject(reto);
            out.flush();
            System.out.println("CLIENTE - Reto enviado al servidor.");

            if (!verificarRetoServidor(reto, (byte[]) in.readObject())) {
                out.writeObject("ERROR");
                out.flush();
                return;
            }

            out.writeObject("OK");
            out.flush();
            System.out.println("CLIENTE - Respuesta enviada al servidor.");

            BigInteger g = (BigInteger) in.readObject();
            BigInteger p = (BigInteger) in.readObject();
            BigInteger gX = (BigInteger) in.readObject();
            byte[] firma = (byte[]) in.readObject();

            if (!verificarFirma(g, p, gX, firma)) {
                out.writeObject("ERROR");
                out.flush();
                return;
            }

            out.writeObject("OK");
            out.flush();

            SecureRandom random = new SecureRandom();
            BigInteger y = new BigInteger(1023, random);
            BigInteger gY = g.modPow(y, p);
            BigInteger gXy = gX.modPow(y, p);
            byte[] secreto = Utilidades.intToBytes(gXy.intValue());

            SecretKey llaveAES = Utilidades.derivarLlaves(secreto)[0];
            SecretKey llaveHMAC = Utilidades.derivarLlaves(secreto)[1];

            out.writeObject(gY);
            out.flush();
            System.out.println("CLIENTE - G^Y enviado al servidor.");

            byte[] iv = new byte[16];
            random.nextBytes(iv);
            out.writeObject(iv);
            out.flush();
            System.out.println("CLIENTE - IV enviado al servidor.");

            byte[] tablaCifrada = (byte[]) in.readObject();
            byte[] hmacTabla = (byte[]) in.readObject();

            if (!verificarHMAC(tablaCifrada, hmacTabla, llaveHMAC)) {
                System.out.println("CLIENTE - Error en verificación de HMAC de la tabla.");
                return;
            }

            Map<Integer, String> tablaServicios = recuperarTablaServicios(tablaCifrada, llaveAES, iv);
            int idElegido = elegirServicio(tablaServicios);
            enviarEleccionServicio(out, idElegido, llaveAES, llaveHMAC, iv);

            long inicioVerif = System.nanoTime();
            recibirDireccionServicio(in, llaveAES, llaveHMAC, iv);
            long finVerif = System.nanoTime();
            double tiempoMs = (finVerif - inicioVerif) / 1_000_000.0;
            MedidorTiempos.escribirTiempo("Verificacion", "Verificacion", tiempoMs);

            out.writeObject("OK");
            out.flush();
            System.out.println("CLIENTE - Protocolo finalizado.");

        } catch (Exception e) {
            System.out.println("Error al iniciar el cliente: " + e.getMessage());
        }
    }

    private boolean verificarRetoServidor(byte[] retoOriginal, byte[] retoCifrado) throws Exception {
        byte[] retoDescifrado = Utilidades.descifrarRSA(retoCifrado, llavePublica);
        return Arrays.equals(retoOriginal, retoDescifrado);
    }

    private boolean verificarFirma(BigInteger g, BigInteger p, BigInteger gX, byte[] firma) throws Exception {
        Signature verificador = Signature.getInstance("SHA256withRSA");
        verificador.initVerify(llavePublica);
        verificador.update(g.toByteArray());
        verificador.update(p.toByteArray());
        verificador.update(gX.toByteArray());
        boolean resultado = verificador.verify(firma);
        System.out.println("CLIENTE - Firma " + (resultado ? "válida." : "inválida."));
        return resultado;
    }

    private boolean verificarHMAC(byte[] datos, byte[] hmacRecibido, SecretKey llaveHMAC) throws Exception {
        byte[] hmacCalculado = Utilidades.hmac(datos, llaveHMAC);
        return Arrays.equals(hmacRecibido, hmacCalculado);
    }

    @SuppressWarnings("unchecked")
    private Map<Integer, String> recuperarTablaServicios(byte[] datosCifrados, SecretKey llaveAES, byte[] iv) throws Exception {
        byte[] datos = Utilidades.descifrarAES(datosCifrados, llaveAES, iv);
        return (Map<Integer, String>) Utilidades.deserializar(datos);
    }

    private int elegirServicio(Map<Integer, String> tabla) {
        ArrayList<Integer> ids = new ArrayList<>(tabla.keySet());
        return ids.get(new Random().nextInt(ids.size()));
    }

    private void enviarEleccionServicio(ObjectOutputStream out, int idServicio, SecretKey llaveAES, SecretKey llaveHMAC, byte[] iv) throws Exception {
        String mensaje = idServicio + ";" + ip;
        byte[] cifrado = Utilidades.cifrarAES(mensaje.getBytes(), llaveAES, iv);
        byte[] hmac = Utilidades.hmac(cifrado, llaveHMAC);
        out.writeObject(cifrado);
        out.flush();
        out.writeObject(hmac);
        out.flush();
    }

    private void recibirDireccionServicio(ObjectInputStream in, SecretKey llaveAES, SecretKey llaveHMAC, byte[] iv) throws Exception {
        byte[] cifrado = (byte[]) in.readObject();
        byte[] hmac = (byte[]) in.readObject();

        if (!verificarHMAC(cifrado, hmac, llaveHMAC)) {
            System.out.println("CLIENTE - Error en HMAC de IP y puerto.");
            return;
        }

        byte[] descifrado = Utilidades.descifrarAES(cifrado, llaveAES, iv);
        String info = new String(descifrado, "UTF-8");
        String[] partes = info.split(";");
        System.out.println("CLIENTE - IP del servicio: " + partes[1] + ", Puerto: " + partes[2]);
    }

    public static String generarIP() {
        Random rand = new Random();
        return rand.nextInt(256) + "." +
               rand.nextInt(256) + "." +
               rand.nextInt(256) + "." +
               rand.nextInt(256);
    }

    @Override
    public void run() {
        iniciarCliente();
    }
}
