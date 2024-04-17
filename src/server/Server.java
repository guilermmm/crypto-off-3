package server;

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.util.Hashtable;

import crypto.AES;
import crypto.B64;
import crypto.Crypto;
import crypto.HMAC;
import crypto.KeyGroup;
import crypto.KeyPair;
import crypto.RSA;
import dbg.Dbg;
import dbg.Dbg.Color;

public class Server implements Runnable {
  DatagramSocket serverSocket = null;
  InetAddress host;
  int port;
  Boolean active = true;
  byte[] receiveBuffer;
  byte[] sendBuffer;
  String message;
  String response;
  DatagramPacket receiveDatagram;
  DatagramPacket sendPacket;
  Hashtable<String, KeyGroup> clients;
  KeyPair publicKey;
  KeyPair privateKey;
  String receiveHeader;

  public Server(int port) {
    clients = new Hashtable<String, KeyGroup>();
    var keys = RSA.generateKeys(true);
    publicKey = keys[0];
    privateKey = keys[1];

    this.port = port;
    Thread t = new Thread(this);
    t.start();

    try {
      t.join();
    } catch (InterruptedException e) {
      e.printStackTrace();
    }
  }

  public void run() {
    try {
      serverSocket = new DatagramSocket(port);
      host = InetAddress.getLocalHost();
      Dbg.log();
      Dbg.log(Color.PURPLE, "Servidor online em: " +
          host +
          ":" +
          port);

      while (active) {
        var res = receiveMessage();

        if (res == null) {
          Dbg.log(Color.RED, "Cliente possivelmente atacante, ignorando...");
          sendMessage("false");
          continue;
        }

        String message = res[0];

        if (message == null) {
          Dbg.log(Color.RED, "Mensagem não autenticada.");
          sendMessage("false");
          continue;
        }

        if (message == "new") {
          continue;
        }

        String port = res[1];

        KeyGroup keyGroup = clients.get(port);

        Dbg.log(Color.BLUE, "Servidor recebeu a mensagem: " + message);

        sendQuery(message);
        var query = receiveQuery().trim();
        sendMessage(query, keyGroup);
      }
    } catch (Exception e) {
      e.printStackTrace();
    } finally {
      // Fechando o servidor.
      if (serverSocket != null)
        serverSocket.close();
    }
  }

  private String[] receiveMessage() throws Exception {
    receiveBuffer = new byte[10240];
    receiveDatagram = new DatagramPacket(
        receiveBuffer,
        receiveBuffer.length);
    serverSocket.receive(receiveDatagram);
    receiveBuffer = receiveDatagram.getData();

    String port = String.valueOf(receiveDatagram.getPort());

    var fullMessage = B64.decode(new String(receiveBuffer));
    receiveHeader = fullMessage.split("/body=")[0];
    var message = fullMessage.split("/body=")[1];

    if (!clients.containsKey(port)) {

      var decryptedFirstMessage = Crypto.decryptFirstMessage(message, privateKey);

      if (decryptedFirstMessage.contains("start")) {

        var clientPublicKey = decryptedFirstMessage.substring(6);

        var hmacKey = HMAC.generateKey();
        var aesKey = AES.generateKey();
        var keyGroup = new KeyGroup(hmacKey, KeyPair.fromString(clientPublicKey), aesKey);

        clients.put(port, keyGroup);

        sendFirstMessage("true:" + keyGroup.toString(), keyGroup.rsaKeyPair,
            header("start", Integer.valueOf(receiveHeader.split(":")[0])));

        return new String[] { "new" };
      }

      sendMessage("false");
      return null;
    }

    try {
      String decryptedMessage = Crypto.decryptMessage(message, clients.get(port));
      return new String[] { decryptedMessage, port };
    } catch (Exception e) {
      Dbg.log(Color.RED, e.getMessage());
      return null;
    }
  }

  private void sendQuery(String message) throws Exception {
    Dbg.log(Color.CYAN_BRIGHT, "Enviando mensagem à base de dados - \"" + message + "\"");
    sendBuffer = B64.encode(message).getBytes();
    sendPacket = new DatagramPacket(
        sendBuffer,
        sendBuffer.length,
        receiveDatagram.getAddress(),
        8080);
    serverSocket.send(sendPacket);
  }

  private String receiveQuery() throws Exception {
    receiveBuffer = new byte[10240];
    receiveDatagram = new DatagramPacket(
        receiveBuffer,
        receiveBuffer.length);
    serverSocket.receive(receiveDatagram);
    return B64.decode(new String(receiveDatagram.getData()).trim());
  }

  private void sendMessage(String message, KeyGroup keyGroup) throws Exception {
    Dbg.log(Color.CYAN_BRIGHT, "Enviando mensagem - \"" + message + "\"");
    String response = B64.encode(header("res", Integer.valueOf(receiveHeader.split(":")[0])) + "/body="
        + Crypto.encryptMessage(message, keyGroup, privateKey));
    sendBuffer = response.getBytes();
    sendPacket = new DatagramPacket(
        sendBuffer,
        sendBuffer.length,
        receiveDatagram.getAddress(),
        5173);
    serverSocket.send(sendPacket);
  }

  private void sendMessage(String message) throws Exception {
    Dbg.log(Color.CYAN_BRIGHT, "Enviando mensagem - \"" + message + "\"");
    String response = B64.encode(header("res", Integer.valueOf(receiveHeader.split(":")[0])) + "/body=" + message);
    sendBuffer = response.getBytes();
    sendPacket = new DatagramPacket(
        sendBuffer,
        sendBuffer.length,
        receiveDatagram.getAddress(),
        5173);
    serverSocket.send(sendPacket);
  }

  private void sendFirstMessage(String message, KeyPair keyPair, String header) throws Exception {
    Dbg.log(Color.CYAN_BRIGHT, "Enviando mensagem - \"" + message + "\"");
    String response = B64.encode(header + "/body=" + Crypto.encryptFirstMessage(message, keyPair));
    sendBuffer = response.getBytes();
    sendPacket = new DatagramPacket(
        sendBuffer,
        sendBuffer.length,
        receiveDatagram.getAddress(),
        5173);
    serverSocket.send(sendPacket);
  }

  private String header(String action, int port) {
    return serverSocket.getLocalPort() + ":" + port + ":" + action;
  }
}
