// <copyright file="CldapTool.cs" company="petrsnd">
// (c) 2024 Daniel F. Peterson (petrsnd@gmail.com)
// </copyright>
namespace CldapTool
{
    using CommandLine;

    internal class ToolOptions
    {
        [Option('s', "Server", Required = true, HelpText = "IP address of the server to ping.")]
        public string? Server { get; set; }

        [Option('p', "Port", Required = false, Default = 389, HelpText = "UDP port of the server.")]
        public int Port { get; set; } = 389;
    }
}
