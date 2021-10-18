public class MainClass {
    public static void main(String[] args) throws Exception {
        // generate test file
        MakeFile.textSource();

        String mode = "ECB", outputName = "resultECB", fileName = "200MBfile";
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