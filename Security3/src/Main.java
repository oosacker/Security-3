import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.PrintWriter;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;

import javax.crypto.Cipher;

public class Main {

	ObjectOutputStream oout;
	ObjectInputStream ois;
	Cipher cipher;
	
	public void generateKeys() throws Exception {
		
		KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
		keyPairGen.initialize(1024);
		KeyPair pair = keyPairGen.generateKeyPair();	
		
		PrivateKey pri = pair.getPrivate();
		PublicKey pub = pair.getPublic();
		
        oout = new ObjectOutputStream(new FileOutputStream("privatekey"));
        oout.writeObject(pri);
        oout.close();
        
        oout = new ObjectOutputStream(new FileOutputStream("publickey"));
        oout.writeObject(pub);
        oout.close();
	}
	
	public KeyPair readKeys() throws Exception{
		
		ois = new ObjectInputStream(new FileInputStream("privatekey"));
		PrivateKey pri = (PrivateKey) ois.readObject();

		ois = new ObjectInputStream(new FileInputStream("publickey"));
		PublicKey pub = (PublicKey) ois.readObject();
		
		return new KeyPair(pub, pri);
			
	}
	
	public byte[] encrypt(byte[] plainText, Key key) throws Exception {
		
		cipher = Cipher.getInstance("RSA");  
        cipher.init(Cipher.ENCRYPT_MODE, key);
        
        return cipher.doFinal(plainText);
        
	}
	
	public byte[] decrypt(byte[] cipherText, Key key) throws Exception {
		
		cipher.init(Cipher.DECRYPT_MODE, key);
         
        return cipher.doFinal(cipherText);    
    
	}
	
	public byte[] digest(byte[] input) throws Exception {
		
		MessageDigest messageDigest = MessageDigest.getInstance("SHA-1");
		
		return messageDigest.digest(input);
		
	}
	
	
//	public void writefile(String filename, String data) throws Exception{
//		
//		PrintWriter writer = new PrintWriter(filename);
//		writer.print(data);
//		writer.close();
//	}
//	
//	public String readfile(String filename) throws Exception{
//		//BufferedReader br = new BufferedReader(new FileReader(filename)); 
//		
//		String data =  new String(Files.readAllBytes(Paths.get(filename))); 
//		
//		//br.close();
//		
//		return data;
//	}
	
	
	public Main() throws Exception {
		
		// Generate RSA key pair and save it
		generateKeys();
		
		// Read the keys from the files - the public key can now be shared
		KeyPair mypair = readKeys();
		
		// My message that I will send
		String myMsg = "This is the message that I will send!!!!";
		System.out.println("My Message: " +myMsg);
		
		// Produce the secure hash of message
		byte[] digest = digest(myMsg.getBytes());
		System.out.println("Message Digest: " +new String(digest, 0, digest.length));
		
		// Encrypt the MD to get digital signature
		byte[] mySig = encrypt(digest, mypair.getPrivate());
		System.out.println("Digital Signature: " +new String(mySig, 0, mySig.length));

		// Save the digital signature to a file - this file can now be sent to other person
		oout = new ObjectOutputStream(new FileOutputStream("signature"));
        oout.writeObject(mySig);
        oout.close();
        
        // Read the digital signature back from file
		ois = new ObjectInputStream(new FileInputStream("signature"));
		byte[] myNewSig = (byte[]) ois.readObject();
		System.out.println("Signature from file: " +new String(myNewSig, 0, myNewSig.length));
		
		// Decrypt it using the public key
		byte[] verify = decrypt(myNewSig, mypair.getPublic());
		System.out.println("Decrypted Signature: " +new String(verify, 0, verify.length));
		
		// Check if correct
		if(Arrays.equals(verify, digest))
			System.out.println("~Signature Verifed~");

	}

	public static void main(String[] args) throws Exception {
		new Main();
	}

}
