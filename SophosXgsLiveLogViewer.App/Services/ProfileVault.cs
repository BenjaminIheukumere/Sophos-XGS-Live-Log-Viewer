using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using SophosXgsLiveLogViewer.App.Models;

namespace SophosXgsLiveLogViewer.App.Services;

public sealed class ProfileVault : IDisposable
{
    private const int CurrentVersion = 1;
    private const int SaltSize = 16;
    private const int NonceSize = 12;
    private const int TagSize = 16;
    private const int KeySize = 32;
    private const int KdfIterations = 600_000;

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true
    };

    private readonly byte[] _key;
    private readonly string _path;
    private readonly byte[] _salt;
    private bool _disposed;

    private ProfileVault(string path, byte[] key, byte[] salt, List<FirewallProfile> profiles)
    {
        _path = path;
        _key = key;
        _salt = salt;
        Profiles = profiles;
    }

    public List<FirewallProfile> Profiles { get; }

    public static string DefaultPath
    {
        get
        {
            var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
            return Path.Combine(appData, "SophosXgsLiveLogViewer", "vault.json");
        }
    }

    public static bool Exists => File.Exists(DefaultPath);

    public static ProfileVault CreateNew(string masterPassword)
    {
        ValidateMasterPassword(masterPassword);

        var salt = RandomNumberGenerator.GetBytes(SaltSize);
        var key = DeriveKey(masterPassword, salt);
        var vault = new ProfileVault(DefaultPath, key, salt, []);
        vault.Save();
        return vault;
    }

    public static ProfileVault Unlock(string masterPassword)
    {
        if (!File.Exists(DefaultPath))
        {
            throw new FileNotFoundException("Vault wurde noch nicht erstellt.", DefaultPath);
        }

        var envelope = JsonSerializer.Deserialize<VaultEnvelope>(File.ReadAllText(DefaultPath), JsonOptions)
            ?? throw new InvalidDataException("Vault-Datei ist leer oder unlesbar.");

        if (envelope.Version != CurrentVersion)
        {
            throw new InvalidDataException($"Vault-Version {envelope.Version} wird nicht unterstützt.");
        }

        var salt = Convert.FromBase64String(envelope.KdfSalt);
        var iterations = envelope.KdfIterations > 0 ? envelope.KdfIterations : KdfIterations;
        var key = DeriveKey(masterPassword, salt, iterations);

        try
        {
            var payload = Decrypt<VaultPayload>(key, envelope.Nonce, envelope.Tag, envelope.Ciphertext)
                ?? new VaultPayload();

            return new ProfileVault(DefaultPath, key, salt, payload.Profiles ?? []);
        }
        catch (CryptographicException ex)
        {
            CryptographicOperations.ZeroMemory(key);
            throw new UnauthorizedAccessException("Masterpasswort ist falsch oder der Vault wurde verändert.", ex);
        }
    }

    public void Save()
    {
        ThrowIfDisposed();

        var payload = new VaultPayload { Profiles = Profiles };
        var encrypted = Encrypt(_key, payload);
        var envelope = new VaultEnvelope
        {
            Version = CurrentVersion,
            Kdf = "PBKDF2-SHA256",
            KdfIterations = KdfIterations,
            KdfSalt = Convert.ToBase64String(_salt),
            Nonce = encrypted.Nonce,
            Tag = encrypted.Tag,
            Ciphertext = encrypted.Ciphertext
        };

        var directory = Path.GetDirectoryName(_path);
        if (!string.IsNullOrWhiteSpace(directory))
        {
            Directory.CreateDirectory(directory);
        }

        var tempPath = _path + ".tmp";
        File.WriteAllText(tempPath, JsonSerializer.Serialize(envelope, JsonOptions), Encoding.UTF8);
        File.Move(tempPath, _path, overwrite: true);
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        CryptographicOperations.ZeroMemory(_key);
        _disposed = true;
    }

    private static void ValidateMasterPassword(string masterPassword)
    {
        if (string.IsNullOrWhiteSpace(masterPassword) || masterPassword.Length < 10)
        {
            throw new ArgumentException("Masterpasswort muss mindestens 10 Zeichen lang sein.");
        }
    }

    private static byte[] DeriveKey(string masterPassword, byte[] salt)
    {
        return DeriveKey(masterPassword, salt, KdfIterations);
    }

    private static byte[] DeriveKey(string masterPassword, byte[] salt, int iterations)
    {
        return Rfc2898DeriveBytes.Pbkdf2(masterPassword, salt, iterations, HashAlgorithmName.SHA256, KeySize);
    }

    private static EncryptedPayload Encrypt<T>(byte[] key, T value)
    {
        var nonce = RandomNumberGenerator.GetBytes(NonceSize);
        var plaintext = JsonSerializer.SerializeToUtf8Bytes(value, JsonOptions);
        var ciphertext = new byte[plaintext.Length];
        var tag = new byte[TagSize];

        using var aes = new AesGcm(key, TagSize);
        aes.Encrypt(nonce, plaintext, ciphertext, tag);
        CryptographicOperations.ZeroMemory(plaintext);

        return new EncryptedPayload(
            Convert.ToBase64String(nonce),
            Convert.ToBase64String(tag),
            Convert.ToBase64String(ciphertext));
    }

    private static T? Decrypt<T>(byte[] key, string nonceBase64, string tagBase64, string ciphertextBase64)
    {
        var nonce = Convert.FromBase64String(nonceBase64);
        var tag = Convert.FromBase64String(tagBase64);
        var ciphertext = Convert.FromBase64String(ciphertextBase64);
        var plaintext = new byte[ciphertext.Length];

        using var aes = new AesGcm(key, TagSize);
        aes.Decrypt(nonce, ciphertext, tag, plaintext);

        try
        {
            return JsonSerializer.Deserialize<T>(plaintext, JsonOptions);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
        }
    }

    private void ThrowIfDisposed()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
    }

    private sealed class VaultEnvelope
    {
        public int Version { get; set; }

        public string Kdf { get; set; } = string.Empty;

        public int KdfIterations { get; set; }

        public string KdfSalt { get; set; } = string.Empty;

        public string Nonce { get; set; } = string.Empty;

        public string Tag { get; set; } = string.Empty;

        public string Ciphertext { get; set; } = string.Empty;
    }

    private sealed class VaultPayload
    {
        public List<FirewallProfile>? Profiles { get; set; }
    }

    private sealed record EncryptedPayload(string Nonce, string Tag, string Ciphertext);
}
