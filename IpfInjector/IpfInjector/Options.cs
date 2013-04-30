using CommandLine;
using CommandLine.Text;

namespace IpfInjector
{
    // Define a class to receive parsed values
    class Options
    {
        [Option('f', "file", Required = true,
          HelpText = "Full path to file, which needs to be injected.")]
        public string InputFile { get; set; }

        [Option('i', "ipf", Required = true,
          HelpText = "Full path to target .IPF archive..")]
        public string IpfArchive { get; set; }

        [Option('p', "path", Required = true,
          HelpText = "Path to file inside ipf archive.")]
        public string PathInsideIpf { get; set; }

        [Option('v', "verbose", DefaultValue = false,
          HelpText = "Prints all messages to standard output.")]
        public bool Verbose { get; set; }

        [ParserState]
        public IParserState LastParserState { get; set; }

        [HelpOption]
        public string GetUsage()
        {
            return HelpText.AutoBuild(this,
              (HelpText current) => HelpText.DefaultParsingErrorsHandler(this, current));
        }
    }
}
