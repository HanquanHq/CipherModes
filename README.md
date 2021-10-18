# Network and Information Security: Block Ciphers
> Date: 2021.10.18
>
> Author: Gong Luyang
>
> Course: Network and Information Security

#### Project Description

Conduct both theoretical and experimental analysis of the five modes of operation for block ciphers defined by NIST. 

The five modes are：

- electronic code book (ECB)
- cipher block chaining (CBC)
- cipher feedback (CFB)
- output feedback (OFB) 
- counter (CTR)

## 1. Introduction: Block Ciphers Modes of Operation

The modes of operation of block ciphers are configuration methods that allow those ciphers to work with large data streams, without the risk of compromising the provided security.

It is not recommended, however it is possible while working with block ciphers, to use the same secret key bits for encrypting the same plaintext parts. Using one deterministic algorithm for a number of identical input data, results in some number of identical ciphertext blocks.

This is a very dangerous situation for the cipher's users. An intruder would be able to get much information by knowing the distribution of identical message parts, even if he would not be able to break the cipher and discover the original messages.

Luckily, there exist ways to blur the cipher output. The idea is to mix the plaintext blocks (which are known) with the ciphertext blocks (which have been just created), and to use the result as the cipher input for the next blocks. As a result, the user avoids creating identical output ciphertext blocks from identical plaintext data. These modifications are called **the block cipher modes of operations**.

### 1.1 ECB (Electronic Codebook) Mode

It is the simplest mode of encryption. Each plaintext block is encrypted separately. Similarly, each ciphertext block is decrypted separately. Thus, it is possible to encrypt and decrypt by using many threads simultaneously. However, in this mode the created ciphertext is not blurred.

##### Encryption in the ECB mode

![encryption in ECB mode](../MD-Notes/docs/images/ECB_encryption.png)



#####  Decryption in the ECB mode

![decryption in ECB mode](../MD-Notes/docs/images/ECB_decryption.png)



A typical example of weakness of encryption using ECB mode is encoding a bitmap image (for example a .bmp file). Even a strong encryption algorithm used in ECB mode cannot blur efficiently the plaintext.

##### An original image

![An original image](../MD-Notes/docs/images/xlogo_original.png.pagespeed.ic.wIhEvDmVuS.webp)



##### An image encrypted using DES ECB

![An image encrypted using DES ECB](../MD-Notes/docs/images/xlogo_des_ecb.png.pagespeed.ic.9PqSiPL6B7.webp)



##### An image encrypted using DES ECB

![An image encrypted using DES CBC](../MD-Notes/docs/images/xlogo_des_cbc.png.pagespeed.ic.Zr10yN5cms.webp)

*The bitmap image encrypted using [DES](http://www.crypto-it.net/eng/symmetric/des.html) and the same secret key. The ECB mode was used for the middle image and the more complicated CBC mode was used for the bottom image.*



A message that is encrypted using the ECB mode should be extended until a size that is equal to an integer multiple of the single block length. A popular method of aligning the length of the last block is about appending an additional bit equal to 1 and then filling the rest of the block with bits equal to 0. It allows to determine precisely the end of the original message. There exist more [methods of aligning the message size](http://www.crypto-it.net/eng/theory/padding.html).

Apart from revealing the hints regarding the content of plaintext, the ciphers that are used in ECB mode are also more vulnerable to [replay attacks](http://www.crypto-it.net/eng/attacks/replay.html).

### 1.2 CBC (Cipher-Block Chaining) Mode

The CBC encryption mode was invented in IBM in 1976. This mode is about adding XOR each plaintext block to the ciphertext block that was previously produced. The result is then encrypted using the cipher algorithm in the usual way. As a result, every subsequent ciphertext block depends on the previous one. The first plaintext block is added XOR to a random initialization vector (commonly referred to as IV). The vector has the same size as a plaintext block.

Encryption in CBC mode can only be performed by using one thread. Despite this disadvantage, this is a very popular way of using block ciphers. CBC mode is used in many applications.

During decrypting of a ciphertext block, one should add XOR the output data received from the decryption algorithm to the previous ciphertext block. Because the receiver knows all the ciphertext blocks just after obtaining the encrypted message, he can decrypt the message using many threads simultaneously.

##### Encryption in the CBC mode

![encryption in CBC mode](../MD-Notes/docs/images/800xNxCBC_encryption.png.pagespeed.ic.1lKdJNF4ZZ.webp)



#####  Decryption in the CBC mode

![decryption in CBC mode](../MD-Notes/docs/images/800xNxCBC_decryption.png.pagespeed.ic.11P63OWRNL.webp)

If one bit of a plaintext message is damaged (for example because of some earlier transmission error), all subsequent ciphertext blocks will be damaged and it will be never possible to decrypt the ciphertext received from this plaintext. As opposed to that, if one ciphertext bit is damaged, only two received plaintext blocks will be damaged. It might be possible to recover the data.

A message that is to be encrypted using the CBC mode, should be [extended](http://www.crypto-it.net/eng/theory/padding.html) till the size that is equal to an integer multiple of a single block length (similarly, as in the case of using the ECB mode).

### Security of the CBC mode

The initialization vector IV should be created randomly by the sender. During transmission it should be concatenated with ciphertext blocks, to allow decryption of the message by the receiver. If an intruder could predict what vector would be used, then the encryption would not be resistant to [chosen-plaintext attacks](http://www.crypto-it.net/eng/attacks/chosen-plaintext.html):

![Schemat ataku CPA na CBC](../MD-Notes/docs/images/xcbc_attack_cpa.png.pagespeed.ic.KziQTOkTWV.webp)



In the example presented above, if the intruder is able to predict that the vector IV1 will be used by the attacked system to produce the response c1, they can guess which one of the two encrypted messages m0 or m1 is carried by the response c1. This situation breaks the rule that the intruder shouldn't be able to distinguish between two ciphertexts even if they have chosen both plaintexts. Therefore, the attacked system is vulnerable to chosen-plaintext attacks.

If the vector IV is generated based on non-random data, for example the user password, it should be encrypted before use. One should use a separate secret key for this activity.

The initialization vector IV should be changed after using the secret key a number of times. It can be shown that even properly created IV used too many times, makes the system vulnerable to chosen-plaintext attacks. For [AES](http://www.crypto-it.net/eng/symmetric/aes.html) cipher it is estimated to be 248 blocks, while for [3DES](http://www.crypto-it.net/eng/symmetric/3des.html) it is about 216 plaintext blocks.

### PCBC (Propagating or Plaintext Cipher-Block Chaining) Mode

The PCBC mode is similar to the previously described CBC mode. It also mixes bits from the previous and current plaintext blocks, before encrypting them. In contrast to the CBC mode, if one ciphertext bit is damaged, the next plaintext block and all subsequent blocks will be damaged and unable to be decrypted correctly.

In the PCBC mode both encryption and decryption can be performed using only one thread at a time.

##### Encryption in the PCBC mode

![encryption in PCBC mode](../MD-Notes/docs/images/800xNxPCBC_encryption.png.pagespeed.ic.XjPWLkrK93.webp)

##### Decryption in the PCBC mode

 

![decryption in PCBC mode](../MD-Notes/docs/images/800xNxPCBC_decryption.png.pagespeed.ic.XkUebeFmNM.webp)



### 1.3 CFB (Cipher Feedback) Mode

The CFB mode is similar to the CBC mode described above. The main difference is that one should encrypt ciphertext data from the previous round (so not the plaintext block) and then add the output to the plaintext bits. It does not affect the cipher security but it results in the fact that the same encryption algorithm (as was used for encrypting plaintext data) should be used during the decryption process.

##### Encryption in the CFB mode

![encryption in CFB mode](../MD-Notes/docs/images/800xNxCFB_encryption.png.pagespeed.ic.NhTtKDkcyq.webp)

##### 

#####  Decryption in the CFB mode

![decryption in CFB mode](../MD-Notes/docs/images/800xNxCFB_decryption.png.pagespeed.ic.JD6LYPVqB6.webp)

##### 

If one bit of a plaintext message is damaged, the corresponding ciphertext block and all subsequent ciphertext blocks will be damaged. Encryption in CFB mode can be performed only by using one thread.

On the other hand, as in CBC mode, one can decrypt ciphertext blocks using many threads simultaneously. Similarly, if one ciphertext bit is damaged, only two received plaintext blocks will be damaged.

As opposed to the previous block cipher modes, the encrypted message doesn't need to be extended till the size that is equal to an integer multiple of a single block length.

### 1.4 OFB (Output Feedback) Mode

Algorithms that work in the OFB mode create keystream bits that are used for encryption subsequent data blocks. In this regard, the way of working of the block cipher becomes similar to the way of working of a typical stream cipher.

##### Encryption in the OFB mode

![encryption in OFB mode](../MD-Notes/docs/images/800xNxOFB_encryption.png.pagespeed.ic.3vNcQasus_.webp)



#####  Decryption in the OFB mode

![decryption in OFB mode](../MD-Notes/docs/images/800xNxOFB_decryption.png.pagespeed.ic.uX8OmA_d1v.webp)

Because of the continuous creation of keystream bits, both encryption and decryption can be performed using only one thread at a time. Similarly, as in the CFB mode, both data encryption and decryption uses the same cipher encryption algorithm.

If one bit of a plaintext or ciphertext message is damaged (for example because of a transmission error), only one corresponding ciphertext or respectively plaintext bit is damaged as well. It is possible to use various correction algorithms to restore the previous value of damaged parts of the received message.

The biggest drawback of OFB is that the repetition of encrypting the initialization vector may produce the same state that has occurred before. It is an unlikely situation but in such a case the plaintext will start to be encrypted by the same data as previously.

### 1.5 CTR (Counter) Mode

Using the CTR mode makes block cipher way of working similar to a stream cipher. As in the OFB mode, keystream bits are created regardless of content of encrypting data blocks. In this mode, subsequent values of an increasing counter are added to a *nonce* value (the nonce means a number that is unique: *number used once*) and the results are encrypted as usual. The nonce plays the same role as initialization vectors in the previous modes.

##### Encryption in the CTR mode

![encryption in CTR mode](../MD-Notes/docs/images/800xNxCTR_encryption.png.pagespeed.ic.Mt7bbLndw-.webp)



#####  Decryption in the CTR mode

![decryption in CTR mode](../MD-Notes/docs/images/800xNxCTR_decryption.png.pagespeed.ic.OylEGJjfKl.webp)



It is one of the most popular block ciphers modes of operation. Both encryption and decryption can be performed using many threads at the same time.

If one bit of a plaintext or ciphertext message is damaged, only one corresponding output bit is damaged as well. Thus, it is possible to use various correction algorithms to restore the previous value of damaged parts of received messages.

The CTR mode is also known as the **SIC** mode (**Segment Integer Counter**).

### Security of the CTR mode

As in the case of the CBC mode, one should change the secret key after using it for encrypting a number of sent messages. It can be proved that the CTR mode generally provides quite good security and that the secret key needs to be changed less often than in the CBC mode.

For example, for the [AES](http://www.crypto-it.net/eng/symmetric/aes.html) cipher the secret key should be changed after about 264 plaintext blocks.



## 2. Performance Analysis

This section will show the results obtained from running the simulation program using different data loads.

In this project, we implement five modes of operation for block cipher. The code has been uploaded to Github, visit https://github.com/HanquanHq/CipherModes for the project.

We generated three txt files of different size: 1MB file, 100MB file, 200MB file. The files are listed as below.

```shell
gongluyang@Extreme MINGW64 /c/workspace/CipherModes/data (master)
$ ll
total 293920
-rw-r--r-- 1 gongluyang 197609  99991552 Oct 18 19:08 100MBfile.txt
-rw-r--r-- 1 gongluyang 197609    991232 Oct 18 19:08 1MBfile.txt
-rw-r--r-- 1 gongluyang 197609 199991296 Oct 18 19:08 200MBfile.txt
```
Then, we record the start time and end time of each mode, and calculate the interval between the two times.

##### Test 1MB file

```
[ECB] Encrypted: 
[cost time(sec)]: 0.0635685
[ECB] Decrypted: 
[cost time(sec)]: 0.0244818

[CBC] Encrypted: 
[cost time(sec)]: 0.0150544
[CBC] Decrypted: 
[cost time(sec)]: 0.0196447

[OFB] Encrypted: 
[cost time(sec)]: 0.0131857
[OFB] Decrypted: 
[cost time(sec)]: 0.0363625

[CFB] Encrypted: 
[cost time(sec)]: 0.0138337
[CFB] Decrypted: 
[cost time(sec)]: 0.0192684

[CTR] Encrypted: 
[cost time(sec)]: 0.0124939
[CTR] Decrypted: 
[cost time(sec)]: 0.007787
```

##### Test 100MB file

```
[ECB] Encrypted: 
[cost time(sec)]: 0.3147166
[ECB] Decrypted: 
[cost time(sec)]: 0.5330812

[CBC] Encrypted: 
[cost time(sec)]: 0.4020458
[CBC] Decrypted: 
[cost time(sec)]: 1.6547126

[OFB] Encrypted: 
[cost time(sec)]: 0.365932
[OFB] Decrypted: 
[cost time(sec)]: 0.5201715

[CFB] Encrypted: 
[cost time(sec)]: 0.3700684
[CFB] Decrypted: 
[cost time(sec)]: 1.6275281

[CTR] Encrypted: 
[cost time(sec)]: 0.4183033
[CTR] Decrypted: 
[cost time(sec)]: 0.3966572
```

##### Test 200MB file

When The time costs of five modes are below:

```
[ECB] Encrypted: 
[cost time(sec)]: 0.3850135
[ECB] Decrypted: 
[cost time(sec)]: 0.8845059

[CBC] Encrypted: 
[cost time(sec)]: 0.6927203
[CBC] Decrypted: 
[cost time(sec)]: 3.1682086

[OFB] Encrypted: 
[cost time(sec)]: 0.7257264
[OFB] Decrypted: 
[cost time(sec)]: 1.2542989

[CFB] Encrypted: 
[cost time(sec)]: 0.7015011
[CFB] Decrypted: 
[cost time(sec)]: 3.31164

[CTR] Encrypted: 
[cost time(sec)]: 0.8337643
[CTR] Decrypted: 
[cost time(sec)]: 0.7845264
```

We can see from the test result that as the amount of data increases, on the cost of encryption and decryption, the ECB and CTR performed better, because CTR is simple. The CBC and CFB costs a longer time when decrypted.

<img src="../MD-Notes/docs/images/image-20211018195650603.png" alt="image-20211018195650603" style="zoom:33%;" />

As for how to choose an encryption/decryption mode, here are some suggestions:

- ECB should not be used if encrypting more than one block of data with the same key.
- CBC, OFB and CFB are similar, however OFB/CFB is better because you only need encryption and not decryption, which can save code space.
- CTR is used if you want good parallelization (ie. speed), instead of CBC/OFB/CFB.
- XTS mode is the most common if you are encoding a random accessible data (like a hard disk or RAM).
- OCB is by far the best mode, as it allows encryption and authentication in a single pass. However there are patents on it in USA.

## 3. Reference

1. https://stackoverflow.com/questions/1220751/how-to-choose-an-aes-encryption-mode-cbc-ecb-ctr-ocb-cfb
2. https://www.cs.wustl.edu/~jain/cse567-06/ftp/encryption_perf/
3. https://en.wikipedia.org/wiki/Block_cipher

## 4. Source Code

Decrypting.java

```java
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;


public class Decrypting {
    private static final String key = "aesEncryptionKey";
    private static final String initVector = "encryptionIntVec";

    public static String Decrypt(byte[] encrypted, String mode) throws Exception{
        IvParameterSpec ivSpec = new IvParameterSpec(initVector.getBytes("UTF-8"));
        SecretKeySpec keySpec = new SecretKeySpec(key.getBytes("UTF-8"), "AES");
        Cipher cipher;

        //System.out.println("input : " + new String(input));
        switch (mode){
            case "ECB":
                cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
                cipher.init(Cipher.ENCRYPT_MODE, keySpec);
                break;
            case "CBC":
                cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
                break;
            case "OFB":
                cipher = Cipher.getInstance("AES/OFB/PKCS5Padding");
                cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
                break;
            case "CFB":
                cipher= Cipher.getInstance("AES/CFB/PKCS5Padding");
                cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
                break;
            case "CTR":
                cipher = Cipher.getInstance("AES/CTR/NoPadding");
                cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
                break;
            default:
                System.out.println("No such mode, default mode: ECB!");
                cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
                cipher.init(Cipher.ENCRYPT_MODE, keySpec);
                break;
        }

        return byteArrayToString(cipher.doFinal(encrypted));
    }

    private static String byteArrayToString(byte[] encrypted) {
        String decryptedMessage = new String(encrypted);
        return decryptedMessage;
    }
}

```

Encrypting.java

```java
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;


public class Encrypting {
    private static final String key = "aesEncryptionKey";
    private static final String initVector = "encryptionIntVec";
    public static byte[] Encrypt(String input, String mode) throws Exception
    {
        IvParameterSpec ivSpec = new IvParameterSpec(initVector.getBytes("UTF-8"));
        SecretKeySpec keySpec = new SecretKeySpec(key.getBytes("UTF-8"), "AES");
        Cipher cipher;

        switch (mode){
            case "ECB":
                cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
                cipher.init(Cipher.ENCRYPT_MODE, keySpec);
                break;
            case "CBC":
                cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
                break;
            case "OFB":
                cipher = Cipher.getInstance("AES/OFB/PKCS5Padding");
                cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
                break;
            case "CFB":
                cipher= Cipher.getInstance("AES/CFB/PKCS5Padding");
                cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
                break;
            case "CTR":
                cipher = Cipher.getInstance("AES/CTR/NoPadding");
                cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
                break;
            default:
                System.out.println("No such mode, default mode: ECB!");
                cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
                cipher.init(Cipher.ENCRYPT_MODE, keySpec);
                break;
        }

        if(mode == "ECB")
            return cipher.doFinal(input.getBytes());
        else
            return cipher.doFinal(input.getBytes("UTF-8"));
    }
}
```

InputOutput.java

```java
import java.io.File;
import java.io.FileNotFoundException;
import java.util.Scanner;

public class InputOutput {
    private static final String key = "aesEncryptionKey";
    private static final String initVector = "encryptionIntVec";
    private static final String pathToFile = "C:\\workspace\\CipherModes\\data\\";

    public static String readFile(String fileName) throws FileNotFoundException {
        var path = pathToFile + fileName + ".txt";
        File file = new File(path);
        Scanner in = new Scanner(file);
        String readSting = in.nextLine();
        return readSting;
    }

    public static byte[] encMode(String mode, String output, String fileName) throws Exception
    {
        String line = "";
        String encResult = "";
        var readSting = readFile(fileName);
        long startTime = System.nanoTime();

        var encryptedMessage = Encrypting.Encrypt(readSting, mode);

        long estimatedTime = System.nanoTime() - startTime;
        double estimatedTimeSec = (double) estimatedTime / 1_000_000_000;
        double estimatedTimeMsec = (double) estimatedTime / 1_000_000;
        //System.out.println("[ms]: "+ estimatedTimeMsec);
        System.out.println("[cost time(sec)]: "+ estimatedTimeSec);
        return encryptedMessage;
    }

    public static void decMode(String mode, byte[] input) throws Exception
    {
        String line = "";
        String decResult = "";
        long startTime = System.nanoTime();

        var decryptedMessage = Decrypting.Decrypt(input, mode);

        long estimatedTime = System.nanoTime() - startTime;
        double estimatedTimeSec = (double) estimatedTime / 1_000_000_000;
        double estimatedTimeMsec = (double) estimatedTime / 1_000_000;

        //System.out.println("[ms]: "+ estimatedTimeMsec);
        System.out.println("[cost time(sec)]: "+ estimatedTimeSec);
    }

    public static String getFull(String name) {
        var xdec = 16 - (name.length() % 16);
        for (int i = 0; i < xdec; i++) {
            name += " ";
        }
        return name;
    }
}
```

MainClass.java

```java
public class MainClass {
    public static void main(String[] args) throws Exception {
        // generate test file
        MakeFile.textSource();

        String mode = "ECB", outputName = "resultECB", fileName = "1MBfile";
        System.out.println("[ECB] Encrypted: ");
        var encryptedMessage = InputOutput.encMode(mode, outputName, fileName);
        System.out.println("[ECB] Decrypted: ");
        InputOutput.decMode(mode, encryptedMessage);

        mode = "CBC";
        outputName = "resultCBC";
        System.out.println("[CBC] Encrypted: ");
        encryptedMessage = InputOutput.encMode(mode, outputName, fileName);
        System.out.println("[CBC] Decrypted: ");
        InputOutput.decMode(mode, encryptedMessage);

        mode = "OFB";
        outputName = "resultOFB";
        System.out.println("[OFB] Encrypted: ");
        encryptedMessage = InputOutput.encMode(mode, outputName, fileName);
        System.out.println("[OFB] Decrypted: ");
        InputOutput.decMode(mode, encryptedMessage);

        mode = "CFB";
        outputName = "resultCFB";
        System.out.println("[CFB] Encrypted: ");
        encryptedMessage = InputOutput.encMode(mode, outputName, fileName);
        System.out.println("[CFB] Decrypted: ");
        InputOutput.decMode(mode, encryptedMessage);

        mode = "CTR";
        outputName = "resultCTR";
        System.out.println("[CTR] Encrypted: ");
        encryptedMessage = InputOutput.encMode(mode, outputName, fileName);
        System.out.println("[CTR] Decrypted: ");
        InputOutput.decMode(mode, encryptedMessage);

        //Tests.CorruptionTest();
    }
}
```

MakeFile.java

```java
import java.io.FileNotFoundException;
import java.io.PrintWriter;

public class MakeFile {

    public static void textSource() throws FileNotFoundException {
        GenerateFile(66666, "1MBfile", "Iam1MBsizefile ");
        GenerateFile(5882353, "100MBfile", "Iam100MBsizefile ");
        GenerateFile(11764705, "200MBfile", "Iam200MBsizefile ");
    }

    public static void GenerateFile(Integer size, String output, String whatWrite) throws FileNotFoundException {
        PrintWriter printer = new PrintWriter("C:\\workspace\\CipherModes\\data\\" + output + ".txt");
        for (int i = 0; i < size; i++) {
            printer.print(whatWrite);
        }
    }
}
```

Tests.java

```java
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class Tests {
    private static final String key = "aesEncryptionKey";
    private static final String initVector = "encryptionIntVec";

    public static void CorruptionTest()
    {
        String originalString = "This is an example sentence that checks the corruption of each mode of the AES cipher";
        System.out.println("Original: " + originalString);
        String encryptedString = encrypt(originalString);
        System.out.println("Encrypted: " + encryptedString);
        Tests.Test(1, originalString);
        Tests.Test(10, originalString);
        Tests.Test(30, originalString);
        Tests.Test(45, originalString);

    }
    public static void Test(int count, String originalString)
    {
        String encryptedString = encrypt(originalString);
        var encryptedStringNew = Base64.getDecoder().decode(encryptedString);
        for(int i=1 ;i<=count; i++)
            encryptedStringNew[i] = 2;
        var changedString = Base64.getEncoder().encodeToString(encryptedStringNew);
        String decryptedString = decrypt(changedString);
        System.out.println("["+ count+ " bits changed] After: " + decryptedString);
        System.out.println(" ");
    }

    public static String encrypt(String value) {
        try {
            //CBC dziala z PKCS5PADDING
            //ECB dziala bez IV
            //OFB dziala z PKCS5PADDING
            //CFB dziala z PKCS5PADDING
            //CTR dziala z NoPadding
            IvParameterSpec iv = new IvParameterSpec(initVector.getBytes("UTF-8"));
            SecretKeySpec skeySpec = new SecretKeySpec(key.getBytes("UTF-8"), "AES");

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);

            byte[] encrypted = cipher.doFinal(value.getBytes());
            return Base64.getEncoder().encodeToString(encrypted);
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return null;
    }

    public static String decrypt(String encrypted) {
        try {
            IvParameterSpec iv = new IvParameterSpec(initVector.getBytes("UTF-8"));
            SecretKeySpec skeySpec = new SecretKeySpec(key.getBytes("UTF-8"), "AES");

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);
            byte[] original = cipher.doFinal(Base64.getDecoder().decode(encrypted));

            return new String(original);
        } catch (Exception ex) {
            ex.printStackTrace();
        }

        return null;
    }
}
```

