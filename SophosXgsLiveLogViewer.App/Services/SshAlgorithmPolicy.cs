using Renci.SshNet;
using SophosXgsLiveLogViewer.App.Models;

namespace SophosXgsLiveLogViewer.App.Services;

public static class SshAlgorithmPolicy
{
    private static readonly string[] StrictKeyExchangeAlgorithms =
    [
        "mlkem768x25519-sha256",
        "sntrup761x25519-sha512",
        "sntrup761x25519-sha512@openssh.com",
        "curve25519-sha256",
        "curve25519-sha256@libssh.org",
        "ecdh-sha2-nistp521",
        "ecdh-sha2-nistp384",
        "ecdh-sha2-nistp256",
        "diffie-hellman-group16-sha512",
        "diffie-hellman-group14-sha256",
        "diffie-hellman-group-exchange-sha256"
    ];

    private static readonly string[] StrictEncryptions =
    [
        "chacha20-poly1305@openssh.com",
        "aes256-gcm@openssh.com",
        "aes128-gcm@openssh.com",
        "aes256-ctr",
        "aes192-ctr",
        "aes128-ctr"
    ];

    private static readonly string[] StrictHmacAlgorithms =
    [
        "hmac-sha2-512-etm@openssh.com",
        "hmac-sha2-256-etm@openssh.com",
        "hmac-sha2-512",
        "hmac-sha2-256"
    ];

    private static readonly string[] StrictHostKeyAlgorithms =
    [
        "ssh-ed25519-cert-v01@openssh.com",
        "ecdsa-sha2-nistp521-cert-v01@openssh.com",
        "ecdsa-sha2-nistp384-cert-v01@openssh.com",
        "ecdsa-sha2-nistp256-cert-v01@openssh.com",
        "rsa-sha2-512-cert-v01@openssh.com",
        "rsa-sha2-256-cert-v01@openssh.com",
        "ssh-ed25519",
        "ecdsa-sha2-nistp521",
        "ecdsa-sha2-nistp384",
        "ecdsa-sha2-nistp256",
        "rsa-sha2-512",
        "rsa-sha2-256"
    ];

    public static void Apply(ConnectionInfo connectionInfo, SshSecurityMode mode)
    {
        if (mode == SshSecurityMode.Compatibility)
        {
            return;
        }

        Restrict(connectionInfo.KeyExchangeAlgorithms, StrictKeyExchangeAlgorithms, "key exchange");
        Restrict(connectionInfo.Encryptions, StrictEncryptions, "encryption");
        Restrict(connectionInfo.HmacAlgorithms, StrictHmacAlgorithms, "MAC");
        Restrict(connectionInfo.HostKeyAlgorithms, StrictHostKeyAlgorithms, "host key");
    }

    public static string Describe(SshSecurityMode mode)
    {
        return mode == SshSecurityMode.Strict
            ? "Strict SSH mode: modern KEX, cipher, MAC and host-key algorithms only."
            : "Compatibility SSH mode: SSH.NET defaults are used, including legacy algorithms for older appliances.";
    }

    private static void Restrict<T>(
        IOrderedDictionary<string, T> algorithms,
        IReadOnlyList<string> preferredAlgorithms,
        string category)
    {
        var allowed = preferredAlgorithms.ToHashSet(StringComparer.Ordinal);

        foreach (var key in algorithms.Keys.ToList())
        {
            if (!allowed.Contains(key))
            {
                algorithms.Remove(key);
            }
        }

        var position = 0;
        foreach (var key in preferredAlgorithms)
        {
            if (algorithms.ContainsKey(key))
            {
                algorithms.SetPosition(key, position++);
            }
        }

        if (algorithms.Count == 0)
        {
            throw new InvalidOperationException($"Strict SSH mode removed all supported {category} algorithms.");
        }
    }
}
