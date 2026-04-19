// Fixture: obfuscated C# script using Base64 and single-char identifiers.
// Used by integration tests to verify obfuscation detection.
public class A {
    // Long Base64 literal that exceeds the 15% ratio threshold:
    string k = "SGVsbG8gV29ybGQhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEh";

    void B() {
        // Single-char variables + XOR decryption pattern
        byte[] d = new byte[] { 0x41, 0x42, 0x43 };
        byte x = 0xAB;
        for (int i = 0; i < d.Length; i++) {
            d[i] = (byte)(d[i] ^ x);
        }
        var c = System.Convert.FromBase64String(k);
    }
}
