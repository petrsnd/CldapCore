// <copyright file="Cldap.cs" company="petrsnd">
// (c) 2024 Daniel F. Peterson (petrsnd@gmail.com)
// </copyright>
namespace Petrsnd.CldapCore
{
    using System;
    using System.DirectoryServices.Protocols;
    using System.Net;
    using System.Net.Sockets;
    using System.Text;

    /// <summary>
    /// This static class provides static methods for sending CLDAP requests.
    /// </summary>
    public static class Cldap
    {
        /// <summary>
        /// Send CLDAP ping request to a target server.
        /// </summary>
        /// <param name="dnsName">DNS name of a naming context.</param>
        /// <param name="ipAddress">IP Address to send CLDAP request to.</param>
        /// <param name="port">Which UDP port to send CLDAP request to. (Default: 389).</param>
        /// <returns>A CLDAP ping response object.</returns>
        /// <exception cref="CldapException">Any failure with CLDAP communication or response parsing.</exception>
        public static PingResponse Ping(string dnsName, IPAddress ipAddress, int port = 389)
        {
            var cldapPing = GetCldapPingRequest(dnsName);
            using (var udpClient = new UdpClient())
            {
                object[] objs;
                try
                {
                    udpClient.Connect(ipAddress, port);
                    var bytesSent = udpClient.Send(cldapPing, cldapPing.Length);
                    if (bytesSent < cldapPing.Length)
                    {
                        throw new CldapException($"Unable to send entire CLDAP ping request, size={cldapPing.Length}");
                    }

                    var remoteIpEndPoint = new IPEndPoint(ipAddress, 0);
                    udpClient.Client.ReceiveTimeout = 10000; // 10 sec
                    var buf = udpClient.Receive(ref remoteIpEndPoint);

                    // This method is based on ber_scanf from winber.h
                    // https://learn.microsoft.com/en-us/windows/win32/api/winber/nf-winber-ber_printf?redirectedfrom=MSDN
                    objs = BerConverter.Decode("{x{x{{x[O]}}}", buf);
                }
                catch (Exception ex)
                {
                    throw new CldapException("Failed to receive and decode CLDAP ping response", ex);
                }

                if (objs == null || objs.Length < 1 || objs[0] == null)
                {
                    throw new CldapException("Decoded CLDAP ping response gave unexpected result");
                }

                return NetlogonResponseDecoder.Decode((byte[])objs[0]);
            }
        }

        private static byte[] GetCldapPingRequest(string dnsName)
        {
            if (dnsName is null)
            {
                dnsName = string.Empty;
            }

            // BerConverter encoding format string
            // https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.protocols.berconverter.encode?view=net-8.0#system-directoryservices-protocols-berconverter-encode(system-string-system-object())
            // Based on ber_printf function from (winber.h)
            // https://learn.microsoft.com/en-us/windows/win32/api/winber/nf-winber-ber_printf?redirectedfrom=MSDN
            // CLDAPMessage
            var buf = BerConverter.Encode(
                "{it{oeeiibt{t{oo}t{oo}}{o}}}", // Encoding format
                1, // Message ID
                0x63, // TAG: protocolOp (Application 3: SearchRequest)
                new byte[] { }, // SearchBase (null LDAP string)
                0, // Scope (0 = baseObject)
                0, // DerefAliases (0 = neverDerefAliases)
                0, // sizeLimit (0)
                0, // timeLimit (1)
                false, // typesOnly (false)
                0xa0, // TAG: filter (0: AND Filter)
                0xa3, // TAG: filter (3: EQUALITY Filter)
                Encoding.ASCII.GetBytes("Host"), // attributeDesc (Octet String)
                Encoding.ASCII.GetBytes(dnsName), // assertionValue (Octet String)
                0xa3, // TAG filter (3: EQUALITY Filter)
                Encoding.ASCII.GetBytes("NtVer"), // attributeDesc (Octet String)
                new byte[] { 0x06, 0x00, 0x00, 0x00 }, // assertionValue (Octet String: DWORD=6 encoded backwards)
                Encoding.ASCII.GetBytes("Netlogon")); // attributes encoded as SEQUENCE [attributeSelector (Octet String)]
            return buf;
        }
    }
}
