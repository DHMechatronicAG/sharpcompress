using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using SharpCompress.Archives.Zip;
using SharpCompress.Common;
using SharpCompress.Common.Zip;
using SharpCompress.Readers;
using SharpCompress.Test.Mocks;
using SharpCompress.Writers;
using SharpCompress.Writers.Zip;
using Xunit;

namespace SharpCompress.Test.Zip;

public class ZipEncryptionWriterTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Zip_Encrypted_OwnershipAndCancellation(bool leaveOpen)
    {
        using var destination = new MemoryStream();
        var options = new ZipWriterOptions(CompressionType.Deflate)
        {
            Password = "password",
            LeaveStreamOpen = leaveOpen,
        };
        await using (var writer = new ZipWriter(destination, options))
        {
            using var input = new MemoryStream(new byte[] { 1, 2, 3 });
            using var cancellation = new CancellationTokenSource();
            cancellation.Cancel();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
                await writer.WriteAsync(
                    "cancelled",
                    input,
                    modificationTime: null,
                    cancellation.Token
                )
            );
            Assert.Equal(0, destination.Length);
            await writer.WriteAsync("data", input, modificationTime: null, CancellationToken.None);
        }
        Assert.Equal(leaveOpen, destination.CanWrite);
    }

    [Fact]
    public void Zip_Encrypted_RejectsUnsupportedOutputBeforeWriting()
    {
        using var destination = new MemoryStream();
        using var forward = new ForwardOnlyStream(destination);
        using var writer = new ZipWriter(
            forward,
            new ZipWriterOptions(CompressionType.Deflate) { Password = "password" }
        );
        Assert.Throws<NotSupportedException>(() =>
            writer.WriteToStream("data", new ZipWriterEntryOptions())
        );
        Assert.Equal(0, destination.Length);
    }

    [Fact]
    public void Zip_Encrypted_RejectsLzmaBeforeWriting()
    {
        using var destination = new MemoryStream();
        using var writer = new ZipWriter(
            destination,
            new ZipWriterOptions(CompressionType.LZMA) { Password = "password" }
        );
        Assert.Throws<NotSupportedException>(() =>
            writer.WriteToStream("data", new ZipWriterEntryOptions())
        );
        Assert.Equal(0, destination.Length);
    }

    public static IEnumerable<object[]> EncryptionCases()
    {
        foreach (
            var encryption in new[]
            {
                ZipEncryptionType.Aes128,
                ZipEncryptionType.Aes256,
                ZipEncryptionType.PkwareTraditional,
            }
        )
        {
            foreach (
                var compression in new[]
                {
                    CompressionType.None,
                    CompressionType.Deflate,
                    CompressionType.BZip2,
                    CompressionType.PPMd,
                    CompressionType.ZStandard,
                }
            )
            {
                foreach (var async in new[] { false, true })
                {
                    yield return new object[] { encryption, compression, async };
                }
            }
        }
    }

    [Theory]
    [MemberData(nameof(EncryptionCases))]
    public async Task Zip_Encrypted_RoundTrip(
        ZipEncryptionType encryption,
        CompressionType compression,
        bool useAsync
    )
    {
        var content = new byte[10003];
        new Random(42).NextBytes(content);
        using var destination = new MemoryStream();
        var options = new ZipWriterOptions(compression)
        {
            Password = "password",
            EncryptionType = encryption,
            LeaveStreamOpen = true,
        };
        if (useAsync)
        {
            await using var output = new AsyncOnlyStream(destination, false);
            await using var writer = await WriterFactory.OpenAsyncWriter(
                output,
                ArchiveType.Zip,
                options,
                CancellationToken.None
            );
            using var input = new MemoryStream(content);
            await writer.WriteAsync("test.bin", input, null, CancellationToken.None);
            using var empty = new MemoryStream();
            await writer.WriteAsync("empty.bin", empty, null, CancellationToken.None);
            await writer.WriteDirectoryAsync("folder", null, CancellationToken.None);
        }
        else
        {
            using var writer = WriterFactory.OpenWriter(destination, ArchiveType.Zip, options);
            using var input = new MemoryStream(content);
            writer.Write("test.bin", input, null);
            using var empty = new MemoryStream();
            writer.Write("empty.bin", empty, null);
            writer.WriteDirectory("folder", null);
        }
        Assert.True(destination.CanWrite);
        destination.Position = 0;
        using (
            var archive = ZipArchive.OpenArchive(
                destination,
                ReaderOptions.ForExternalStream with
                {
                    Password = "password",
                }
            )
        )
        {
            var entries = archive.Entries.ToArray();
            Assert.Equal(3, entries.Length);
            Assert.True(entries[0].IsEncrypted);
            using var extracted = new MemoryStream();
            using (var stream = entries[0].OpenEntryStream())
            {
                stream.CopyTo(extracted);
            }
            Assert.Equal(content, extracted.ToArray());
            using var empty = entries[1].OpenEntryStream();
            Assert.Equal(-1, empty.ReadByte());
            Assert.True(entries[2].IsDirectory);
            Assert.False(entries[2].IsEncrypted);
        }
        destination.Position = 0;
        await using var asyncArchive = await ZipArchive.OpenAsyncArchive(
            destination,
            ReaderOptions.ForExternalStream with
            {
                Password = "password",
            },
            CancellationToken.None
        );
        var first = await asyncArchive.EntriesAsync.FirstAsync();
        using var entryStream = await first.OpenEntryStreamAsync(CancellationToken.None);
        using var result = new MemoryStream();
        await entryStream.CopyToAsync(result, 81920, CancellationToken.None);
        Assert.Equal(content, result.ToArray());
    }

    [Theory]
    [InlineData(ZipEncryptionType.Aes128, false)]
    [InlineData(ZipEncryptionType.Aes256, false)]
    [InlineData(ZipEncryptionType.Aes256, true)]
    [InlineData(ZipEncryptionType.PkwareTraditional, false)]
    [InlineData(ZipEncryptionType.PkwareTraditional, true)]
    public void Zip_Encrypted_ChunkedWrites(ZipEncryptionType encryption, bool zip64)
    {
        using var destination = new MemoryStream();
        var content = Encoding.UTF8.GetBytes(
            "Data crossing multiple AES blocks in irregular chunks."
        );
        using (
            var writer = new ZipWriter(
                destination,
                new ZipWriterOptions(CompressionType.None)
                {
                    Password = "password",
                    EncryptionType = encryption,
                    UseZip64 = zip64,
                }
            )
        )
        using (var entry = writer.WriteToStream("test.txt", new ZipWriterEntryOptions()))
        {
            for (var i = 0; i < content.Length; i += 3)
            {
                entry.Write(content, i, Math.Min(3, content.Length - i));
            }
        }
        destination.Position = 0;
        using var reader = ReaderFactory.OpenReader(
            destination,
            ReaderOptions.ForExternalStream with
            {
                Password = "password",
            }
        );
        Assert.True(reader.MoveToNextEntry());
        using var data = reader.OpenEntryStream();
        using var extracted = new MemoryStream();
        data.CopyTo(extracted);
        Assert.Equal(content, extracted.ToArray());
        Assert.False(reader.MoveToNextEntry());
    }

    [Fact]
    public void Zip_Encrypted_RejectsWrongPassword()
    {
        using var destination = new MemoryStream();
        using (
            var writer = new ZipWriter(
                destination,
                new ZipWriterOptions(CompressionType.Deflate) { Password = "password" }
            )
        )
        using (var input = new MemoryStream(Encoding.UTF8.GetBytes("secret")))
        {
            writer.Write("test.txt", input);
        }
        destination.Position = 0;
        using var archive = ZipArchive.OpenArchive(
            destination,
            ReaderOptions.ForExternalStream with
            {
                Password = "wrong",
            }
        );
        Assert.ThrowsAny<Exception>(() =>
        {
            using var stream = archive.Entries.First().OpenEntryStream();
            stream.CopyTo(Stream.Null);
        });
    }
}
