
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.io.ObjectInputStream;
import java.net.Socket;
import java.util.Random;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.net.SocketFactory;



public class CryptoClient {
    public static void main(String[] args) throws IOException, ClassNotFoundException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException{
	FileInputStream fis = new FileInputStream("public.bin");
	ObjectInputStream oInStream = new ObjectInputStream(fis);
	RSAPublicKey rPK = (RSAPublicKey)oInStream.readObject();
	Cipher cipher = Cipher.getInstance("AES");
        Key key = KeyGenerator.getInstance("AES").generateKey();
        Cipher rsaCipher = Cipher.getInstance("RSA");
        rsaCipher.init(Cipher.ENCRYPT_MODE, rPK);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        CryptoDriver cd = new CryptoDriver(rPK,rsaCipher,  cipher, key);
        cd.initialize();
    }

}

class UdpClient {

    private short sourcePort = 0b0101010101010101;
    private short length;
    private short checksum;
    private short[] header;
    private int shortBitMask = 0x0000FFFF;
    private long sourceIPAddress;
    private long destinationIPAddress;

    public UdpClient(long sourceIP, long destIP) {
	sourceIPAddress = sourceIP;
	destinationIPAddress = destIP;
    }

   private long generateChecksum(short[] data, long sIp, long dIp) {
	long sum = 0;
	short[] fullSum = new short[(data.length + 6)];
	for (int i = 0; i < data.length; ++i) {
	    fullSum[i] = data[i];
	}

	fullSum[data.length + 1] |= sIp;
	fullSum[data.length] |= (sIp >>> 16);
	fullSum[data.length + 3] |= dIp;
	fullSum[data.length + 2] |= (dIp >>> 16);
	// length calc twice
	fullSum[data.length + 4] |= data[2];
	fullSum[data.length + 5] |= 17;// It will never not be udp

	for (int i = 0; i < fullSum.length; ++i) {
	    sum += ((fullSum[i]) & shortBitMask);

	    if ((sum & 0xffff0000) > 0) {
		// carry occurred
		sum &= shortBitMask;
		sum++;
	    }

	}
	return ~(sum & shortBitMask);
    }

    public short[] generatePacket(short[] input, short destinationPort) {
	length = (short) (4 + input.length);
	short[] packet = new short[length];
	packet[0] |= sourcePort;
	packet[1] |= destinationPort;
	packet[2] |= (2 * length);
	packet[3] = 0;
	for (int i = 0; i < input.length; ++i) {
	    packet[i + 4] = input[i];
	}
	packet[3] = (short) generateChecksum(packet, sourceIPAddress,
		destinationIPAddress);
	return packet;
    }


    public byte[] thisBytes(short[] data) {
	int j = 0;
	byte[] result = new byte[(data.length << 1)];

	for (int i = 0; i < data.length; ++i) {
	    result[j + 1] |= (data[i] & 0xFF);
	    data[i] >>>= 8;
	    result[j] |= (data[i] & 0xFF);
	    j += 2;
	}
	return result;
    }
}

class IPV4Client {

    private byte version = 0b00000100;
    private byte tOS = 0b00000000; // do not implement as per instructions
    private byte timeToLive = 50;
    private byte protocol = 0x11;
    private byte internetHeaderLength = 5;
    private int totalLength = 0;
    private int identification = 0;
    // Flags and fragment offset combined.Flags = 010, No fragmentation
    private int flagsFragsOffset = 0b0100000000000000;
    private int headerChecksum = 0;
    private int shortBitMask = 0x0000FFFF;
    // 127.0.0.1
    public long sourceIPAddress = 0b01111111000000000000000000000001;
    // 76.91.123.97
    public long destinationIPAddress = 0b01001100010110110111101101100001;

    public short[] createPacket(short[] data) {
	// Calculate total length in shorts
	totalLength = data.length + (internetHeaderLength * 2);
	// Break things if length is invalid
	if (totalLength > 32767 || totalLength < 0) {
	    return null;
	}

	short temp = 0;
	long tempLong = 0;
	short[] checkSum = new short[totalLength];

	// Store version, then shift left by 12 to push the 4 version bits to
	// the front
	checkSum[0] = version;
	checkSum[0] <<= 12;
	// Get the internetHeaderLength bits into the correct spot
	temp = internetHeaderLength;
	temp <<= 8;

	checkSum[0] |= temp;
	checkSum[0] |= tOS;
	// Multiply total length by 2 to get length in bytes
	totalLength *= 2;
	checkSum[1] |= totalLength;

	checkSum[2] |= identification;
	checkSum[3] |= flagsFragsOffset;

	checkSum[4] |= (timeToLive & 0xFF);
	checkSum[4] <<= 8;
	checkSum[4] |= (protocol & 0xFF);

	checkSum[5] |= headerChecksum;
	// Note 7 is given a value first. This spares the use of a temporary
	// variable
	checkSum[7] |= sourceIPAddress;
	checkSum[6] |= (sourceIPAddress >>> 16);
	// Note 9 is given a value first
	checkSum[9] |= destinationIPAddress;
	checkSum[8] |= (destinationIPAddress >>> 16);
	// Store the passed data in slots 10-x of the array. Starts at 10 to
	// avoid overwriting the header
	for (int i = 0; i < data.length; ++i) {
	    checkSum[i + 10] = data[i];
	}

	long checksum = generateChecksum(checkSum);
	checkSum[5] |= checksum;

	return checkSum;

    }
    
    public byte[] createPacket(byte[] data) {
	// Calculate total length in bytes
	totalLength = data.length + (internetHeaderLength * 4);
	System.out.println("Lenght of data is: "+ totalLength);

	byte temp = 0;
	long tempLong = 0;
	byte[] checkSum = new byte[totalLength];

	// Store version, then shift left by 12 to push the 4 version bits to
	// the front
	checkSum[0] = version;
	checkSum[0] <<= 4;
	// Get the internetHeaderLength bits into the correct spot
	temp = internetHeaderLength;
	temp&= 0b00001111;

	checkSum[0] |= temp;
	checkSum[1] |= tOS;
	// Multiply total length by 2 to get length in bytes
	checkSum[3] |= totalLength;
	System.out.println(totalLength >>>8);
	checkSum[2] |= (totalLength >>> 8);

	checkSum[5] |= identification;
	checkSum[4] |= (identification >>>8);
	
	
	checkSum[7] |= flagsFragsOffset;
	checkSum[6] |= (flagsFragsOffset >>>8);

	checkSum[8] |= (timeToLive & 0xFF);
	checkSum[9] |= (protocol & 0xFF);

	checkSum[11] |= headerChecksum;
	checkSum[10] |= (headerChecksum >>>8);
	// Note 7 is given a value first. This spares the use of a temporary
	// variable
	checkSum[15] |= sourceIPAddress;
	checkSum[14] |= (sourceIPAddress >>>8);
	checkSum[13] |= (sourceIPAddress >>> 16);
	checkSum[12] |= (sourceIPAddress >>>24);
	// Note 9 is given a value first
	checkSum[19] |= destinationIPAddress;
	checkSum[18] |= (destinationIPAddress >>>8);
	checkSum[17] |= (destinationIPAddress >>> 16);
	checkSum[16] |= (destinationIPAddress >>>24);
	// Store the passed data in slots 10-x of the array. Starts at 10 to
	// avoid overwriting the header
	for (int i = 0; i < data.length; ++i) {
	    checkSum[i + 20] = data[i];
	}

	long checksum = generateChecksum(checkSum);
	checkSum[11] |= checksum;
	checkSum[10] |= (checksum >>>8);

	return checkSum;

    }



    private long generateChecksum(byte[] bytes) {
	long sum = 0;
	short[] data = byteToShort(bytes);
	for (int i = 0; i < 10; ++i) {
	    sum += ((data[i]) & shortBitMask);

	    if ((sum & 0xffff0000) > 0) {
		// carry occurred
		sum &= shortBitMask;
		sum++;
	    }

	}
	return ~(sum & shortBitMask);
    }
    
    private long generateChecksum(short[] bytes) {
   	long sum = 0;
   	for (int i = 0; i < 10; ++i) {
   	    sum += ((bytes[i]) & shortBitMask);

   	    if ((sum & 0xffff0000) > 0) {
   		// carry occurred
   		sum &= shortBitMask;
   		sum++;
   	    }

   	}
   	return ~(sum & shortBitMask);
       }
    
    private short[] byteToShort(byte[] b){
   	short[] result = new short[(b.length + 1) /2];
   	for(int i = 0, j =0; j< b.length -1 ; ++i, j+=2){
   	    result[i] |= b[j];
   	    result[i] <<= 8;
   	    result[i] |= b[j+1];
   	}
   	return result;
       }

    public byte[] thisBytes(short[] data) {
	byte[] byteMessage = new byte[data.length * 2];
	for (int i = 0, j = 0; i < data.length; i++, j += 2)
	{
		byteMessage[j + 1] |= data[i];
		data[i] >>>= 8;
		byteMessage[j] |= data[i];
	}

	return byteMessage;
    }

}

class CryptoDriver {
    
    private RSAPublicKey rpk;
    private Cipher cipher;
    private Key key;
    private Cipher rsaCipher;
    
    public CryptoDriver(RSAPublicKey rpk, Cipher rsaCipher, Cipher cipher, Key key){
	this.rpk = rpk;
	this.cipher = cipher;
	this.key = key;
	this.rsaCipher = rsaCipher;
    }
	//Where the differences from the previous project begin
    public void initialize() throws IOException, IllegalBlockSizeException, BadPaddingException {
	IPV4Client ipv = new IPV4Client();
	UdpClient udp = new UdpClient(ipv.sourceIPAddress,
		ipv.destinationIPAddress);
	
	
	Random r = new Random();
	
	//Serialize the AES key
	ByteArrayOutputStream baos = new ByteArrayOutputStream();
	ObjectOutputStream oos = new ObjectOutputStream(baos);
	oos.writeObject(key);
	//Is this correct?
	byte[] temp = rsaCipher.doFinal(baos.toByteArray());

	//Create an ip packet using temp as the data, turn that into an array of bytes(from an array of shorts)
	byte[] sendThis = ipv.createPacket(temp);
	printPacket(sendThis);

	try {

	    Socket socket = SocketFactory.getDefault().createSocket(
		    "76.91.123.97", 22222);

	    if (socket.isConnected()) {
		System.out.println("Connection to server made");
	    }

	    OutputStream outputStream = socket.getOutputStream();
	    InputStream br = socket.getInputStream();
	    outputStream.write(sendThis);
		
		long roundTrip = 0;
	    for (int i = 0; i < 10; ++i) {

		byte[] s = new byte[(int) Math.pow(2, (i +1))];
		for (int j = 0; j < s.length; ++j) {
		    s[j] = (byte) r.nextInt();
		}
		short[] pureUdp = udp.generatePacket(byteToShort(s), (short) 0b101011011001110);
		byte[] toSend = cipher.doFinal(ipv.thisBytes(ipv.createPacket(pureUdp)));
		//System.out.print("The port in the package is: "+ Integer.toHexString(toSend[22]));

		//System.out.println(Integer.toHexString(toSend[23]) );
		Long startTime = System.currentTimeMillis();
		outputStream.write(toSend);
		//Read 4 byte response& print it
		Long endTime = System.currentTimeMillis();
		roundTrip += (endTime - startTime);
		System.out.print(Integer.toHexString(br.read()));
		System.out.print(Integer.toHexString(br.read()));
		System.out.print(Integer.toHexString(br.read()));
		System.out.println(Integer.toHexString(br.read()));
		System.out.println("Took: " + (endTime-startTime) + "ms");
	    }
	    System.out.println("Average time = "  + (roundTrip/10) + "ms");

	} catch (Exception e) {
	    // Connection failed, abort without grace
	    e.printStackTrace();
	}

    }
    
    

    public void printPacket(byte[] sendIt) {
	for (int i = 0; i < sendIt.length; ++i) {
	    String temp = Integer.toBinaryString(sendIt[i]);

	    if (i % 4 == 0) {
		System.out.println();
	    }
	    while (temp.length() < 8) {
		temp += ("0" + temp);
	    }
	    System.out.print(temp.substring(temp.length() - 8) + " ");

	}
    }
    
    private short[] byteToShort(byte[] b){
	short[] result = new short[(b.length + 1) /2];
	for(int i = 0, j =0; j< b.length -1 ; ++i, j+=2){
	    result[i] |= b[j];
	    result[i] <<= 8;
	    result[i] |= b[j+1];
	}
	return result;
    }
}
