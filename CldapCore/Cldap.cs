namespace Petrsnd.CldapCore
{
    using System;
    using System.DirectoryServices.Protocols;
    using System.Net.Sockets;
    using System.Net;
    using System.Text;

    public static class Cldap
    {
        private static byte[] GetCldapPingRequest(string dnsName)
        {
            var buf = BerConverter.Encode("{it{oeeiibt{t{oo}t{oo}}{o}}}",
                // CLDAPMessage
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
                                                       // attributes, encoded as SEQUENCE
                Encoding.ASCII.GetBytes("Netlogon")); // attributeSelector (Octet String)
            return buf;
        }

        public static PingResponse Ping(string dnsName, IPAddress ipAddress, int port)
        {
            var cldapPing = GetCldapPingRequest(dnsName);
            using (var udpClient = new UdpClient())
            {
                object[] objs;
                try
                {
                    udpClient.Connect(ipAddress, port);
                    udpClient.Send(cldapPing, cldapPing.Length);
                    var remoteIpEndPoint = new IPEndPoint(ipAddress, 0);
                    udpClient.Client.ReceiveTimeout = 10000; // 10 sec
                    var buf = udpClient.Receive(ref remoteIpEndPoint);
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
    }
}
