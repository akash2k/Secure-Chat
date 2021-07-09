import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.Scanner;

public class Client {


    private JPanel MainPanel;
    private JLabel TopLabel;
    private JTextArea ShowMsg;
    private JLabel WriteLabel;
    private JTextField InputField;
    private JButton SendButton;
    static String secKey;
    static double Adash;
    static String recvd;

    static ObjectOutputStream oos;
    static ObjectInputStream ois;
    static Socket socket;



    private static SecretKeySpec secretKey;
    private static byte[] key;

    public static String getHash(String input)
    {
        try {
            // getInstance() method is called with algorithm SHA-512
            MessageDigest md = MessageDigest.getInstance("SHA-512");

            // digest() method is called
            // to calculate message digest of the input string
            // returned as array of byte
            byte[] messageDigest = md.digest(input.getBytes());

            // Convert byte array into signum representation
            BigInteger no = new BigInteger(1, messageDigest);

            // Convert message digest into hex value
            String hashtext = no.toString(16);

            // Add preceding 0s to make it 32 bit
            while (hashtext.length() < 32) {
                hashtext = "0" + hashtext;
            }

            // return the HashText
            return hashtext;
        }

        // For specifying wrong message digest algorithms
        catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    public static void setKey(String myKey) {
        MessageDigest sha = null;
        try {
            key = myKey.getBytes(StandardCharsets.UTF_8);
            sha = MessageDigest.getInstance("SHA-1");
            key = sha.digest(key);
            key = Arrays.copyOf(key, 16);
            secretKey = new SecretKeySpec(key, "AES");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public static String encrypt(String strToEncrypt, String secret) {
        try {
            setKey(secret);
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            return Base64.getEncoder().encodeToString(cipher.doFinal(strToEncrypt.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            System.out.println("Error while encrypting: " + e.toString());
        }
        return null;
    }

    public static String decrypt(String strToDecrypt, String secret) {
        try {
            setKey(secret);
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5PADDING");
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            return new String(cipher.doFinal(Base64.getDecoder().decode(strToDecrypt)));
        } catch (Exception e) {
            System.out.println("Error while decrypting: " + e.toString());
        }
        return null;
    }

    public void SetValue(String msg){
        this.ShowMsg.append(msg);
    }

    public Client() {
        SendButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {

                    String outmsg = InputField.getText();
                    InputField.setText("");
                    System.out.println(outmsg);
                    ShowMsg.append("\nYou: " + outmsg);
                outmsg = outmsg + "&&" + getHash(outmsg);

                try {
                    oos.writeObject(encrypt(outmsg, secKey));
                } catch (IOException ex) {
                    ex.printStackTrace();
                }

            }
        });
    }

    public static void main(String[] args) throws IOException, ClassNotFoundException, InterruptedException {

        Client obj=new Client();
        JFrame frame = new JFrame("Client");
        frame.setContentPane(obj.MainPanel);
        frame.setSize(500, 400);
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        //frame.pack();
        frame.setVisible(true);

        SecureRandom secRan = new SecureRandom();
        Scanner sc = new Scanner(System.in);
        InetAddress host = InetAddress.getLocalHost();
        socket = new Socket(host.getHostName(), 9876);
        System.out.println("Connecting to server");
        System.out.println("Just connected to " + socket.getRemoteSocketAddress());
        oos = new ObjectOutputStream(socket.getOutputStream());
        ois = new ObjectInputStream(socket.getInputStream());

        try {

            String pstr, gstr, Astr;

            // Declare p, g, and Key of client
            int p = 59;
            int g = 13;
            int a = secRan.nextInt(10) + 1;
            double serverB;

            pstr = Integer.toString(p);
            oos.writeObject(pstr); // Sending p

            gstr = Integer.toString(g);
            oos.writeObject(gstr); // Sending g

            double A = ((Math.pow(g, a)) % p); // calculation of A
            Astr = Double.toString(A);
            oos.writeObject(Astr); // Sending A

            // Client's Private Key
            System.out.println("\nFrom Client : Private Key = " + a);

            serverB = Double.parseDouble((String) ois.readObject());
            System.out.println("From Server : Public Key = " + serverB);

            Adash = ((Math.pow(serverB, a)) % p); // calculation of Adash

            System.out.println("Secret Key to perform Symmetric Encryption = " + Adash);

            secKey = Double.toString(Adash);
            String recvd = "";
            while (!recvd.equals("Exit")) {

                String asdf = (String) ois.readObject();
                recvd = decrypt(asdf, secKey);
                String[] message = recvd.split("&&");
                if (!getHash(message[0]).equals(message[1])) System.out.println("Authentication failed!!!");
                obj.SetValue("\nServer: " + message[0]);
                System.out.println("\nServer: " + message[0]);
                System.out.println(asdf);
            }
            ois.close();
            oos.close();
            socket.close();
            System.out.println("Connection terminated");
        } catch (Exception e) {
            e.printStackTrace();
        }

    }
}