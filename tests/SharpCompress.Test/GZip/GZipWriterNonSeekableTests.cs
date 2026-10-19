using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using SharpCompress.Archives.GZip;
using SharpCompress.Test.Mocks;
using SharpCompress.Writers.GZip;
using Xunit;

namespace SharpCompress.Test.GZip;

/// <summary>
/// Regression tests for writing gzip streams to non-seekable (forward-only) output streams.
/// GZip is inherently a single forward stream with no seek-dependent layout, so streaming to
/// a <see cref="ForwardOnlyStream"/> must simply produce a valid, readable gzip stream.
/// </summary>
public class GZipWriterNonSeekableTests
{
    private const string EntryName = "content.txt";

    private static byte[] CreateContent() =>
        Encoding.UTF8.GetBytes(string.Concat(Enumerable.Repeat("Hello streaming gzip! ", 500)));

    private static async Task<byte[]> WriteToNonSeekableAsync(byte[] content)
    {
        using var ms = new MemoryStream();
        await using (var writer = new GZipWriter(new ForwardOnlyStream(ms)))
        {
            using var source = new MemoryStream(content);
            await writer.WriteAsync(EntryName, source, null);
        }
        return ms.ToArray();
    }

    private static byte[] WriteToNonSeekableSync(byte[] content)
    {
        using var ms = new MemoryStream();
        using (var writer = new GZipWriter(new ForwardOnlyStream(ms)))
        {
            using var source = new MemoryStream(content);
            writer.Write(EntryName, source, null);
        }
        return ms.ToArray();
    }

    private static void AssertRoundTrips(byte[] gz, byte[] expected)
    {
        using var archive = GZipArchive.OpenArchive(new MemoryStream(gz));
        var entry = archive.Entries.First();
        using var extracted = new MemoryStream();
        using (var entryStream = entry.OpenEntryStream())
        {
            entryStream.CopyTo(extracted);
        }
        Assert.Equal(expected, extracted.ToArray());
    }

    [Fact]
    public async Task GZip_Async_NonSeekable_RoundTrips()
    {
        var content = CreateContent();
        var gz = await WriteToNonSeekableAsync(content);
        AssertRoundTrips(gz, content);
    }

    [Fact]
    public void GZip_Sync_NonSeekable_RoundTrips()
    {
        var content = CreateContent();
        var gz = WriteToNonSeekableSync(content);
        AssertRoundTrips(gz, content);
    }
}
