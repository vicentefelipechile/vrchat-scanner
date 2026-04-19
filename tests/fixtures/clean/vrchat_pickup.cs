using UdonSharp;
using UnityEngine;
using VRC.SDK3.Components;

// Fixture: legitimate VRChat / UdonSharp behaviour.
// Expected: score < 35 (CLEAN or LOW) even with UnityWebRequest present
// because the VRChat SDK context reduces HTTP findings.
public class VRChatPickup : UdonSharpBehaviour {
    public VRCPickup pickup;
    public string displayName = "Mystery Box";

    public override void OnPickup() {
        Debug.Log("Picked up: " + displayName);
    }

    public override void OnDrop() {
        Debug.Log("Dropped: " + displayName);
    }
}
