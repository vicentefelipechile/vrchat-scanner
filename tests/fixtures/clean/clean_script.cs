using UnityEngine;

// Fixture: a safe, minimal VRChat script with no suspicious APIs.
// Integration tests expect score < 30 (CLEAN) for this script.
public class CleanBehaviour : MonoBehaviour {
    private string message = "Hello VRChat!";

    void Start() {
        Debug.Log(message);
    }

    void Update() {
        // Nothing suspicious here
    }
}
