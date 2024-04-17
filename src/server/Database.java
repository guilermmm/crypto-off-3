package server;

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.util.Hashtable;

import crypto.B64;
import crypto.HashPassword;
import dbg.Dbg;
import dbg.Dbg.Color;

public class Database implements Runnable {
  DatagramSocket databaseSocket = null;
  InetAddress host;
  int port;
  Boolean active = true;
  byte[] receiveBuffer;
  byte[] sendBuffer;
  String message;
  String response;
  DatagramPacket receiveDatagram;
  DatagramPacket sendPacket;
  Hashtable<String, User> users;

  public Database(int port) {
    users = new Hashtable<String, User>();

    User u = new User("123.123.123-12", "123", "Cayo Perico", "Rua das Oiticicas, 33", "(84) 91236-4432", "1");
    u.deposit(10000.00f, "1");

    users.put("1", u);
    users.put("2", new User("123.123.123-12", "123", "Jão Mouras", "Rua das Seticicas, 44", "(84) 91236-4432", "2"));
    users.put("3", new User("123.123.123-12", "123", "Henri Theus", "Rua das Novicicas, 55", "(84) 91236-4432", "3"));

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
      databaseSocket = new DatagramSocket(port);
      host = InetAddress.getByName("localhost");
      Dbg.log();
      Dbg.log(Color.PURPLE, "Base de dados online em: " +
          host +
          ":" +
          port);

      while (active) {
        message = receiveMessage();

        if (message.contains("body")) {
          var m = message.split("body=")[1];
          String[] params = m.split("/")[1].split(":");
          deposit(params[0], params[1], params[2]);
          continue;
        }

        if (message.contains("info")) {
          sendMessage(users.toString());
          continue;
        }

        String[] parted = message.split("/");
        String route = parted[0];
        String[] params = parted[1].split(":");

        switch (route) {
          case "login":
            login(params[0], params[1]);
            break;
          case "signup":
            signUp(params[0], params[1], params[2], params[3], params[4]);
            break;
          case "withdraw":
            withdraw(params[0], params[1], params[2]);
            break;
          case "deposit":
            deposit(params[0], params[1], params[2]);
            sendMessage("true");
            break;
          case "balance":
            response = balance(params[0], params[1]);
            sendMessage(response);
            break;
          case "transfer":
            response = transfer(params[0], params[1], params[2]);
            sendMessage(response);
            break;
          case "investment":
            response = investment(params[0], params[1]);
            sendMessage(response);
            break;

          default:
            continue;
        }

      }
    } catch (Exception e) {
      e.printStackTrace();
    }
  }

  public void login(String accountNumber, String password) throws Exception {
    User user = users.get(accountNumber);

    if (user == null) {
      sendMessage("false");
      return;
    }

    if (user.lockedUntil < System.currentTimeMillis() && user.attempts >= 3) {
      user.attempts = 0;
      user.lockedUntil = 0;
    }

    var hashedPassword = HashPassword.hash(password.trim(), user.accountNumber.getBytes());

    if (!user.password.equals(hashedPassword)) {
      user.attempts++;
      if (user.attempts >= 3) {
        user.lockedUntil = System.currentTimeMillis() + 10000;

        sendMessage("false:locked");
        return;
      }

      sendMessage("false:" + (3 - user.attempts));
      return;
    }

    sendMessage("true");
  }

  public void signUp(String name, String cpf, String password, String address, String phone)
      throws Exception {
    String accountNumber = String.valueOf(users.size() + 1);

    users.put(accountNumber, new User(cpf, password, name, address, phone, accountNumber));

    sendMessage("true:" + accountNumber);
  }

  public void withdraw(String accountNumber, String accountType, String value) throws Exception {
    User user = users.get(accountNumber);

    if (user == null) {
      sendMessage("Usuário não existe.");
      return;
    }

    Boolean w = user.withdraw(Float.parseFloat(value), accountType);

    if (!w) {
      sendMessage("Saldo insuficiente.");
      return;
    }

    sendMessage("true");
  }

  public void deposit(String accountNumber, String accountType, String value) throws Exception {
    User user = users.get(accountNumber);

    if (user == null) {
      sendMessage("Usuário não existe.");
      return;
    }

    user.deposit(Float.parseFloat(value), accountType);

  }

  public String transfer(String accountNumber, String destinationNumber, String value) {
    User user = users.get(accountNumber);
    User destinationUser = users.get(destinationNumber);

    if (user == null)
      return "Usuário não existe.";

    if (destinationUser == null)
      return "Usuário de destino não existe.";

    Boolean w = user.withdraw(Float.parseFloat(value), "1");

    if (!w)
      return "Saldo insuficiente.";

    destinationUser.deposit(Float.parseFloat(value), "1");

    return "true";
  }

  public String balance(String accountNumber, String accountType) {
    User user = users.get(accountNumber);

    if (user == null) {
      return "Usuário não existe.";
    }

    return "R$" + user.balance(accountType);
  }

  public String investment(String accountNumber, String accountType) {
    User user = users.get(accountNumber);

    if (user == null) {
      return "Usuário não existe.";
    }

    return "R$" + user.balance(accountType);
  }

  private void sendMessage(String message) throws Exception {
    Dbg.log(Color.CYAN_BRIGHT, "Enviando mensagem ao servidor - \"" + message + "\"");
    sendBuffer = B64.encode(message).getBytes();
    sendPacket = new DatagramPacket(
        sendBuffer,
        sendBuffer.length,
        receiveDatagram.getAddress(),
        5050);
    databaseSocket.send(sendPacket);
  }

  private String receiveMessage() throws Exception {
    receiveBuffer = new byte[10240];
    receiveDatagram = new DatagramPacket(
        receiveBuffer,
        receiveBuffer.length);
    databaseSocket.receive(receiveDatagram);
    var message = B64.decode(new String(receiveDatagram.getData()).trim());
    Dbg.log(Color.BLUE, "Recebendo mensagem do servidor - \"" + message + "\"");
    return message;
  }

}
