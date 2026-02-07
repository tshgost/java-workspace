import java.io.IOException;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Scanner;

/**
 * A simple, line-oriented TCP echo server.
 *
 * <p>The server accepts one client at a time, reads incoming text line-by-line,
 * and sends each line back to the same client.
 *
 * <p>Usage:
 * <pre>
 *   java EchoServer [port]
 * </pre>
 *
 * <p>Behavior details:
 * <ul>
 *   <li>If no port is provided, the default port {@value #DEFAULT_PORT} is used.</li>
 *   <li>If a non-numeric or out-of-range port is provided, the default port is used.</li>
 *   <li>When the client sends {@code bye}, the server echoes it and closes that client session.</li>
 *   <li>The server continues running and waits for the next client connection.</li>
 * </ul>
 */
public class EchoServer {
    private static final int DEFAULT_PORT = 12345;
    private static final int MIN_PORT = 1;
    private static final int MAX_PORT = 65535;
    private static final String EXIT_COMMAND = "bye";

    private final int port;

    /**
     * Creates an echo server configured to listen on the provided port.
     *
     * @param port valid TCP port number
     */
    public EchoServer(int port) {
        this.port = port;
    }

    public static void main(String[] args) {
        int port = parsePort(args);
        EchoServer server = new EchoServer(port);
        server.start();
    }

    /**
     * Parses the command-line port argument.
     *
     * @param args command-line args passed to main
     * @return valid port or {@link #DEFAULT_PORT} when invalid input is provided
     */
    private static int parsePort(String[] args) {
        if (args.length == 0) {
            return DEFAULT_PORT;
        }

        if (args.length > 1) {
            System.err.println("Extra arguments detected. Only the first argument is used as port.");
        }

        try {
            int parsedPort = Integer.parseInt(args[0]);
            if (parsedPort < MIN_PORT || parsedPort > MAX_PORT) {
                System.err.println("Port out of range (" + MIN_PORT + "-" + MAX_PORT + "): " + parsedPort);
                System.err.println("Falling back to default port " + DEFAULT_PORT);
                return DEFAULT_PORT;
            }
            return parsedPort;
        } catch (NumberFormatException ex) {
            System.err.println("Invalid port: " + args[0]);
            System.err.println("Falling back to default port " + DEFAULT_PORT);
            return DEFAULT_PORT;
        }
    }

    /**
     * Starts the server socket loop.
     */
    public void start() {
        System.out.println("Echo server starting on port " + port + "...");
        System.out.println("Send '" + EXIT_COMMAND + "' to close a client connection.");

        int connectionCount = 0;

        try (ServerSocket serverSocket = new ServerSocket(port)) {
            while (true) {
                Socket clientSocket = serverSocket.accept();
                connectionCount++;
                handleClient(clientSocket, connectionCount);
            }
        } catch (IOException ex) {
            System.err.println("Could not start server on port " + port + ": " + ex.getMessage());
        }
    }

    /**
     * Handles a single client session until the stream closes or EXIT_COMMAND is received.
     *
     * @param clientSocket accepted client socket
     * @param connectionId incremental connection number for logs
     */
    private void handleClient(Socket clientSocket, int connectionId) {
        try (Socket socket = clientSocket;
                Scanner in = new Scanner(socket.getInputStream());
                PrintWriter out = new PrintWriter(socket.getOutputStream(), true)) {
            String clientAddress = socket.getRemoteSocketAddress().toString();
            int lineCount = 0;

            System.out.println("[Connection #" + connectionId + "] Connected: " + clientAddress);

            while (in.hasNextLine()) {
                String line = in.nextLine();
                lineCount++;
                out.println(line);

                if (EXIT_COMMAND.equalsIgnoreCase(line.trim())) {
                    break;
                }
            }

            System.out.println("[Connection #" + connectionId + "] Disconnected: " + clientAddress
                    + " | echoed lines: " + lineCount);
        } catch (IOException ex) {
            System.err.println("[Connection #" + connectionId + "] Client connection error: " + ex.getMessage());
        }
    }
}
