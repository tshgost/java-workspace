import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;

/**
 * A simple TCP echo server.
 *
 * Usage:
 *   java EchoServer [port]
 */
public class EchoServer {
    private static final int DEFAULT_PORT = 12345;

    public static void main(String[] args) {
        int port = DEFAULT_PORT;

        if (args.length > 0) {
            try {
                port = Integer.parseInt(args[0]);
            } catch (NumberFormatException ex) {
                System.err.println("Invalid port: " + args[0]);
                System.err.println("Falling back to default port " + DEFAULT_PORT);
                port = DEFAULT_PORT;
            }
        }

        System.out.println("Echo server starting on port " + port + "...");

        try (ServerSocket serverSocket = new ServerSocket(port)) {
            while (true) {
                try (Socket clientSocket = serverSocket.accept();
                        BufferedReader in = new BufferedReader(
                                new InputStreamReader(clientSocket.getInputStream()));
                        PrintWriter out = new PrintWriter(clientSocket.getOutputStream(), true)) {

                    String clientAddress = clientSocket.getRemoteSocketAddress().toString();
                    System.out.println("Connected: " + clientAddress);

                    String line;
                    while ((line = in.readLine()) != null) {
                        out.println(line);
                        if ("bye".equalsIgnoreCase(line.trim())) {
                            break;
                        }
                    }

                    System.out.println("Disconnected: " + clientAddress);
                } catch (IOException ex) {
                    System.err.println("Client connection error: " + ex.getMessage());
                }
            }
        } catch (IOException ex) {
            System.err.println("Could not start server on port " + port + ": " + ex.getMessage());
        }
    }
}
