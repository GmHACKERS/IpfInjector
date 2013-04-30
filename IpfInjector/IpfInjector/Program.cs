using System;
using System.IO;
using System.Linq;
using Ionic.Zip;

namespace IpfInjector
{
    class Program
    {
        private static void Main(string[] args)
        {
            var options = new Options();
            if (CommandLine.Parser.Default.ParseArguments(args, options))
            {
                var injection = new FileInjection
                    {
                        EntryName = options.PathInsideIpf,
                        PathToIpf = options.IpfArchive,
                        PathToFile = options.InputFile
                    };

                if (options.Verbose)
                    Console.WriteLine("Starting injection [{0}] into [{1}]", options.InputFile, options.IpfArchive);

                InjectFile(injection, options.Verbose);
                
                Console.WriteLine("Injection finished :)");

                if (options.Verbose) Console.Read();
            }
        }

        private static void InjectFile(FileInjection fileInjection, bool verbose)
        {
            if (!File.Exists(fileInjection.PathToFile))
                throw new Exception("Injection file does not exists");
            if (verbose) Console.WriteLine("Injection file found");

            if (!File.Exists(fileInjection.PathToIpf))
                throw new Exception("Ipf file does not exists");
            if (verbose) Console.WriteLine("Ipf file found");

            var folderNameInsideIpf = Path.GetDirectoryName(fileInjection.EntryName);
            using (var zip = ZipFile.Read(fileInjection.PathToIpf))
            {
                // Add element with normal name.
                var entry = zip.AddFile(fileInjection.PathToFile, folderNameInsideIpf);
                // Calculate encoded name.
                var encryptedName = Chiper.EncodeString(entry.FileName, zip.AlternateEncoding);
                // Delete element if exists.
                var result = zip.Any(e => e.FileName.EndsWith(encryptedName));
                if (result)
                {
                    if (verbose) Console.WriteLine("Element already exists => Replacing");
                    zip.RemoveEntry(encryptedName);
                }
                // Renaming.
                entry.FileName = encryptedName;
                entry.Password = zip.AlternateEncoding.GetString(Chiper.Password);
                entry.Encryption = EncryptionAlgorithm.PkzipWeak;
                // Write archive.
                zip.Save(fileInjection.PathToIpf);
            }
        }
    }
}
