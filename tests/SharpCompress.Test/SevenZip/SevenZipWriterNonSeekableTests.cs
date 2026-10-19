using System.IO;
using SharpCompress.Common;
using SharpCompress.Test.Mocks;
using SharpCompress.Writers.SevenZip;
using Xunit;

namespace SharpCompress.Test.SevenZip;

/// <summary>
/// 7z writing requires a seekable output stream so the signature header can be back-patched on
/// finalize (see SevenZipWriter.cs). Unlike Zip, it cannot fall back to a streaming layout, so
/// constructing a writer over a non-seekable output must fail fast. This pins that documented
/// limitation against silent regression.
/// </summary>
public class SevenZipWriterNonSeekableTests
{
    [Fact]
    public void SevenZip_NonSeekable_Output_Throws()
    {
        using var ms = new MemoryStream();
        Assert.Throws<ArchiveOperationException>(() =>
            new SevenZipWriter(new ForwardOnlyStream(ms), new SevenZipWriterOptions())
        );
    }
}
