// <copyright file="CldapTool.cs" company="petrsnd">
// (c) 2024 Daniel F. Peterson (petrsnd@gmail.com)
// </copyright>
namespace CldapTool
{
    using CommandLine;

    internal class ToolOptions
    {
        [Option('d', "Server", Required = true, HelpText = "DNS name of a naming context.")]
        public string? DnsName { get; set; }

        [Option('a', "IpAddress", Required = true, HelpText = "IP address of the server.")]
        public string? IpAddress { get; set; }

        [Option('p', "Port", Required = false, Default = 389, HelpText = "UDP port of the server.")]
        public int Port { get; set; } = 389;
    }
}
