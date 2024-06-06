// <copyright file="Program.cs" company="petrsnd">
// (c) 2024 Daniel F. Peterson (petrsnd@gmail.com)
// </copyright>
namespace CldapTool
{
    using System.Net;
    using CommandLine;
    using Petrsnd.CldapCore;

    internal class Program
    {
        private static void Execute(ToolOptions opts)
        {
            try
            {
                var ipAddress = IPAddress.Parse(opts.Server!);
                var response = Cldap.Ping(ipAddress, null, opts.Port);
                Console.WriteLine(response);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Fatal exception occurred: {ex}");
                Console.WriteLine(ex.StackTrace);
                Environment.Exit(1);
            }
        }

        private static void HandleParseError(IEnumerable<Error> errors)
        {
            Console.WriteLine("Invalid command line options");
            Environment.Exit(1);
        }

        private static void Main(string[] args) =>
            Parser.Default.ParseArguments<ToolOptions>(args)
                .WithParsed(Execute)
                .WithNotParsed(HandleParseError);
    }
}
