package hbea;

public class SecureMessenger {

    private Cipher cipher;

    public SecureMessenger(Cipher cipher) {
        this.cipher = cipher;
    }

    public void setCipher(Cipher cipher) {
        this.cipher = cipher;
    }

    public String send(String plaintext) throws InvalidMessageException {
        return cipher.encrypt(plaintext);
    }

    public String receive(String cipherHex) {
        return cipher.decrypt(cipherHex);
    }

    public String getCipherName() {
        return cipher.getName();
    }
}