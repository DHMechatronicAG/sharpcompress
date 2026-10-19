using System;
using System.Buffers.Binary;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using SharpCompress.IO;

namespace SharpCompress.Common.Zip;

/// <summary>
/// Stream that encrypts data using WinZip AES encryption and writes to an underlying stream.
/// </summary>
internal partial class WinzipAesEncryptionStream : Stream, IAsyncDisposable
{
    private const int BLOCK_SIZE_IN_BYTES = 16;
    private const int RFC2898_ITERATIONS = 1000;
    private const int AUTH_CODE_LENGTH = 10;

    private readonly Stream _stream;
    private readonly Aes _cipher;
    private readonly ICryptoTransform _transform;
    private readonly HMACSHA1 _hmac;
    private readonly byte[] _counter = new byte[BLOCK_SIZE_IN_BYTES];
    private readonly byte[] _counterOut = new byte[BLOCK_SIZE_IN_BYTES];
    private int _nonce = 1;
    private int _keyStreamOffset = BLOCK_SIZE_IN_BYTES;
    private readonly byte[] _header;
    private bool _isDisposed;

    private WinzipAesEncryptionStream(Stream stream, string password, WinzipAesKeySize keySize)
    {
        _stream = stream;

        // Generate salt
        var saltLength = GetSaltLength(keySize);
        var salt = new byte[saltLength];
        using (var rng = RandomNumberGenerator.Create())
        {
            rng.GetBytes(salt);
        }

        // WinZip AES requires PBKDF2-HMAC-SHA1; changing the hash breaks the format.
#pragma warning disable CA5379
        // Derive keys using PBKDF2
        var keyLength = GetKeyLength(keySize);

#if NETFRAMEWORK || NETSTANDARD2_0
        using var rfc2898 = new Rfc2898DeriveBytes(password, salt, RFC2898_ITERATIONS);
        var keyBytes = rfc2898.GetBytes(keyLength);
        var ivBytes = rfc2898.GetBytes(keyLength);
        var passwordVerifyValue = rfc2898.GetBytes(2);
#elif NET10_0_OR_GREATER
        var derivedKeySize = (keyLength * 2) + 2;
        var passwordBytes = Encoding.UTF8.GetBytes(password);
        var derivedKey = Rfc2898DeriveBytes.Pbkdf2(
            passwordBytes,
            salt,
            RFC2898_ITERATIONS,
            HashAlgorithmName.SHA1,
            derivedKeySize
        );
        var keyBytes = derivedKey.AsSpan(0, keyLength).ToArray();
        var ivBytes = derivedKey.AsSpan(keyLength, keyLength).ToArray();
        var passwordVerifyValue = derivedKey.AsSpan(keyLength * 2, 2).ToArray();
#else
        using var rfc2898 = new Rfc2898DeriveBytes(
            password,
            salt,
            RFC2898_ITERATIONS,
            HashAlgorithmName.SHA1
        );
        var keyBytes = rfc2898.GetBytes(keyLength);
        var ivBytes = rfc2898.GetBytes(keyLength);
        var passwordVerifyValue = rfc2898.GetBytes(2);
#endif

#pragma warning restore CA5379
        // Initialize cipher
        _cipher = CreateCipher(keyBytes);
        var iv = new byte[BLOCK_SIZE_IN_BYTES];
        _transform = _cipher.CreateEncryptor(keyBytes, iv);

        // Initialize HMAC for authentication
        // WinZip AES mandates HMAC-SHA1 for interoperability.
#pragma warning disable CA5350
        _hmac = new HMACSHA1(ivBytes);
#pragma warning restore CA5350

        // Write salt and password verification value
        _header = new byte[salt.Length + passwordVerifyValue.Length];
        salt.CopyTo(_header, 0);
        passwordVerifyValue.CopyTo(_header, salt.Length);
    }

    internal static WinzipAesEncryptionStream Create(
        Stream stream,
        string password,
        WinzipAesKeySize keySize
    )
    {
        var result = new WinzipAesEncryptionStream(stream, password, keySize);
        stream.Write(result._header, 0, result._header.Length);
        return result;
    }

    internal static async ValueTask<WinzipAesEncryptionStream> CreateAsync(
        Stream stream,
        string password,
        WinzipAesKeySize keySize,
        CancellationToken cancellationToken
    )
    {
        var result = new WinzipAesEncryptionStream(stream, password, keySize);
        await stream
            .WriteAsync(result._header, 0, result._header.Length, cancellationToken)
            .ConfigureAwait(false);
        return result;
    }

    private static int GetSaltLength(WinzipAesKeySize keySize) =>
        keySize switch
        {
            WinzipAesKeySize.KeySize128 => 8,
            WinzipAesKeySize.KeySize192 => 12,
            WinzipAesKeySize.KeySize256 => 16,
            _ => throw new InvalidOperationException(),
        };

    private static int GetKeyLength(WinzipAesKeySize keySize) =>
        keySize switch
        {
            WinzipAesKeySize.KeySize128 => 16,
            WinzipAesKeySize.KeySize192 => 24,
            WinzipAesKeySize.KeySize256 => 32,
            _ => throw new InvalidOperationException(),
        };

    private static Aes CreateCipher(byte[] keyBytes)
    {
        var cipher = Aes.Create();
        cipher.BlockSize = BLOCK_SIZE_IN_BYTES * 8;
        cipher.KeySize = keyBytes.Length * 8;
        cipher.Mode = CipherMode.ECB;
        cipher.Padding = PaddingMode.None;
        return cipher;
    }

    public override bool CanRead => false;

    public override bool CanSeek => false;

    public override bool CanWrite => true;

    public override long Length => throw new NotSupportedException();

    public override long Position
    {
        get => throw new NotSupportedException();
        set => throw new NotSupportedException();
    }

    public override void Flush() => _stream.Flush();

    public override Task FlushAsync(CancellationToken cancellationToken) =>
        _stream.FlushAsync(cancellationToken);

    public override int Read(byte[] buffer, int offset, int count) =>
        throw new NotSupportedException();

    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

    public override void SetLength(long value) => throw new NotSupportedException();

    public override void Write(byte[] buffer, int offset, int count)
    {
        if (count == 0)
        {
            return;
        }

        var encrypted = EncryptData(buffer, offset, count);
        _hmac.TransformBlock(encrypted, 0, encrypted.Length, encrypted, 0);
        _stream.Write(encrypted, 0, encrypted.Length);
    }

    public override async Task WriteAsync(
        byte[] buffer,
        int offset,
        int count,
        CancellationToken cancellationToken
    )
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (count == 0)
        {
            return;
        }
        var encrypted = EncryptData(buffer, offset, count);
        _hmac.TransformBlock(encrypted, 0, encrypted.Length, encrypted, 0);
        await _stream
            .WriteAsync(encrypted, 0, encrypted.Length, cancellationToken)
            .ConfigureAwait(false);
    }

#if !LEGACY_DOTNET
    public override ValueTask WriteAsync(
        ReadOnlyMemory<byte> buffer,
        CancellationToken cancellationToken = default
    )
    {
        var bytes = buffer.ToArray();
        return new ValueTask(WriteAsync(bytes, 0, bytes.Length, cancellationToken));
    }
#endif

#if NET48 || NETSTANDARD2_0
    public async ValueTask DisposeAsync()
#else
    public override async ValueTask DisposeAsync()
#endif
    {
        if (_isDisposed)
        {
            return;
        }
        _isDisposed = true;
        try
        {
            _hmac.TransformFinalBlock([], 0, 0);
            await _stream.WriteAsync(_hmac.Hash!, 0, AUTH_CODE_LENGTH).ConfigureAwait(false);
        }
        finally
        {
            _transform.Dispose();
            _cipher.Dispose();
            _hmac.Dispose();
        }
        GC.SuppressFinalize(this);
#if !NET48 && !NETSTANDARD2_0
        await base.DisposeAsync().ConfigureAwait(false);
#endif
    }

    private byte[] EncryptData(byte[] buffer, int offset, int count)
    {
        var result = new byte[count];
        for (var i = 0; i < count; i++)
        {
            // Keep unused keystream bytes across writes; compressor chunk sizes are arbitrary.
            if (_keyStreamOffset == BLOCK_SIZE_IN_BYTES)
            {
                BinaryPrimitives.WriteInt32LittleEndian(_counter, _nonce++);
                _transform.TransformBlock(_counter, 0, BLOCK_SIZE_IN_BYTES, _counterOut, 0);
                _keyStreamOffset = 0;
            }
            result[i] = (byte)(_counterOut[_keyStreamOffset++] ^ buffer[offset + i]);
        }
        return result;
    }

    protected override void Dispose(bool disposing)
    {
        if (_isDisposed)
        {
            return;
        }
        _isDisposed = true;

        if (disposing)
        {
            // Finalize HMAC and write authentication code
            _hmac.TransformFinalBlock([], 0, 0);
            var authCode = _hmac.Hash!;
            _stream.Write(authCode, 0, AUTH_CODE_LENGTH);

            _transform.Dispose();
            _cipher.Dispose();
            _hmac.Dispose();
            _stream.Dispose();
        }

        base.Dispose(disposing);
    }

    /// <summary>
    /// Gets the overhead bytes added by encryption (salt + password verification + auth code).
    /// </summary>
    internal static int GetEncryptionOverhead(WinzipAesKeySize keySize) =>
        GetSaltLength(keySize) + 2 + AUTH_CODE_LENGTH;
}
