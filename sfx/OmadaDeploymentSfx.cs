using System;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Security.Principal;
using System.Text;

internal static class OmadaDeploymentSfx
{
    private static readonly byte[] Magic = Encoding.ASCII.GetBytes("OMADAWGPKG00001");

    [STAThread]
    private static int Main(string[] args)
    {
        string self = Process.GetCurrentProcess().MainModule.FileName;
        if (!IsAdministrator())
        {
            try
            {
                Process.Start(new ProcessStartInfo(self, "--elevated") {
                    UseShellExecute = true,
                    Verb = "runas"
                });
                return 0;
            }
            catch
            {
                return 2;
            }
        }

        string temporary = Path.Combine(Path.GetTempPath(), "omada-wg-" + Guid.NewGuid().ToString("N"));
        try
        {
            Directory.CreateDirectory(temporary);
            ExtractPayload(self, temporary);
            string installer = Path.Combine(temporary, "Install-Company-VPN.exe");
            if (!File.Exists(installer))
                throw new InvalidDataException("The embedded VPN installer is missing.");
            using (Process child = Process.Start(new ProcessStartInfo(installer) {
                UseShellExecute = false,
                WorkingDirectory = temporary
            }))
            {
                child.WaitForExit();
                if (child.ExitCode != 0)
                    return child.ExitCode;
            }
            ScheduleSelfDelete(self);
            return 0;
        }
        catch (Exception error)
        {
            System.Windows.Forms.MessageBox.Show(
                error.Message, "Company VPN Setup", System.Windows.Forms.MessageBoxButtons.OK,
                System.Windows.Forms.MessageBoxIcon.Error);
            return 2;
        }
        finally
        {
            try { Directory.Delete(temporary, true); } catch { }
        }
    }

    private static bool IsAdministrator()
    {
        WindowsIdentity identity = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    }

    private static void ExtractPayload(string self, string destination)
    {
        using (FileStream source = new FileStream(self, FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            if (source.Length < Magic.Length + 8)
                throw new InvalidDataException("This deployment executable has no embedded payload.");
            source.Seek(-Magic.Length, SeekOrigin.End);
            byte[] magic = new byte[Magic.Length];
            source.Read(magic, 0, magic.Length);
            if (Encoding.ASCII.GetString(magic) != Encoding.ASCII.GetString(Magic))
                throw new InvalidDataException("This deployment executable has an invalid payload marker.");
            source.Seek(-(Magic.Length + 8), SeekOrigin.End);
            byte[] lengthBytes = new byte[8];
            source.Read(lengthBytes, 0, 8);
            long payloadLength = BitConverter.ToInt64(lengthBytes, 0);
            long payloadOffset = source.Length - Magic.Length - 8 - payloadLength;
            if (payloadLength <= 0 || payloadOffset < 0)
                throw new InvalidDataException("This deployment executable has an invalid payload length.");
            source.Seek(payloadOffset, SeekOrigin.Begin);
            using (MemoryStream payload = new MemoryStream())
            {
                CopyBytes(source, payload, payloadLength);
                payload.Position = 0;
                using (ZipArchive archive = new ZipArchive(payload, ZipArchiveMode.Read))
                {
                    string root = Path.GetFullPath(destination) + Path.DirectorySeparatorChar;
                    foreach (ZipArchiveEntry entry in archive.Entries)
                    {
                        string target = Path.GetFullPath(Path.Combine(destination, entry.FullName));
                        if (!target.StartsWith(root, StringComparison.OrdinalIgnoreCase))
                            throw new InvalidDataException("The embedded package contains an invalid path.");
                        if (String.IsNullOrEmpty(entry.Name))
                        {
                            Directory.CreateDirectory(target);
                            continue;
                        }
                        Directory.CreateDirectory(Path.GetDirectoryName(target));
                        using (Stream input = entry.Open())
                        using (FileStream output = new FileStream(target, FileMode.Create, FileAccess.Write))
                            input.CopyTo(output);
                    }
                }
            }
        }
    }

    private static void CopyBytes(Stream input, Stream output, long count)
    {
        byte[] buffer = new byte[81920];
        while (count > 0)
        {
            int read = input.Read(buffer, 0, (int)Math.Min(buffer.Length, count));
            if (read <= 0) throw new EndOfStreamException();
            output.Write(buffer, 0, read);
            count -= read;
        }
    }

    private static void ScheduleSelfDelete(string self)
    {
        string escaped = self.Replace("\"", "\"\"");
        Process.Start(new ProcessStartInfo("cmd.exe",
            "/d /c \"ping 127.0.0.1 -n 3 >nul & del /f /q \"\"" + escaped + "\"\"\"") {
            UseShellExecute = false,
            CreateNoWindow = true,
            WindowStyle = ProcessWindowStyle.Hidden
        });
    }
}
