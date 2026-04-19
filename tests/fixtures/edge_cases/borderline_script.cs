// Fixture: a C# script that represents a borderline/edge case.
// Has environment variable access and marshal — MEDIUM risk, not CRITICAL.
using System;
using System.Runtime.InteropServices;

public class BorderlineScript : MonoBehaviour {
    void Collect() {
        string user = Environment.UserName;
        string host = Environment.MachineName;
        IntPtr buf = Marshal.AllocHGlobal(256);
        Marshal.FreeHGlobal(buf);
    }
}
