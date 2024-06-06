// <copyright file="NetlogonResponseDecoder.cs" company="petrsnd">
// (c) 2024 Daniel F. Peterson (petrsnd@gmail.com)
// </copyright>
namespace Petrsnd.CldapCore
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Runtime.InteropServices;
    using System.Text;

    /// <summary>
    /// Operation code of a CLDAP ping request or response.
    /// </summary>
    internal enum Opcode : ushort
    {
        /// <summary>
        /// Mailslot ping query to determine if the server is a primary.
        /// </summary>
        LOGON_PRIMARY_QUERY = 7,

        /// <summary>
        /// Mailslot ping response of whether the server is a primary.
        /// </summary>
        LOGON_PRIMARY_RESPONSE = 12,

        /// <summary>
        /// Mailslot ping request.
        /// </summary>
        LOGON_SAM_LOGON_REQUEST = 18,

        /// <summary>
        /// Mailslot ping response.
        /// </summary>
        LOGON_SAM_LOGON_RESPONSE = 19,

        /// <summary>
        /// Mailslot ping response indicating netlogon service is in paused state.
        /// </summary>
        LOGON_SAM_PAUSE_RESPONSE = 20,

        /// <summary>
        /// Mailslot response with unknown user.
        /// </summary>
        LOGON_SAM_USER_UNKNOWN = 21,

        /// <summary>
        /// Mailslot ping response with data.
        /// </summary>
        LOGON_SAM_LOGON_RESPONSE_EX = 23,

        /// <summary>
        /// Mailslot ping response indicating netlogon service is in paused state. (Extended).
        /// </summary>
        LOGON_SAM_PAUSE_RESPONSE_EX = 24,

        /// <summary>
        /// Mailslot response with unknown user. (Extended).
        /// </summary>
        LOGON_SAM_USER_UNKNOWN_EX = 25,
    }

    /// <summary>
    /// Directory service flags.
    /// </summary>
    internal enum DS_FLAG : uint
    {
        /// <summary>
        /// The server holds the PDC FSMO role (PdcEmulationMasterRole).
        /// FSMO roles are defined in [MS-ADTS] section 3.1.1.1.11. Certain
        /// updates can be performed only on the holder of the PDC FSMO role.
        /// </summary>
        DS_PDC_FLAG = 0x00000001,

        /// <summary>
        /// The server is a GC server and will accept and process messages directed
        /// to it on the global catalog ports ([MS-ADTS] section 3.1.1.3.1.10).
        /// </summary>
        DS_GC_FLAG = 0x00000004,

        /// <summary>
        /// The server is an LDAP server.
        /// </summary>
        DS_LDAP_FLAG = 0x00000008,

        /// <summary>
        /// The server is a DC.
        /// </summary>
        DS_DS_FLAG = 0x00000010,

        /// <summary>
        /// The server is running the Kerberos Key Distribution Center service.
        /// </summary>
        DS_KDC_FLAG = 0x00000020,

        /// <summary>
        /// The Win32 Time Service, as specified in [MS-W32T], is present on the server.
        /// </summary>
        DS_TIMESERV_FLAG = 0x00000040,

        /// <summary>
        /// The server is in the same site as the client. This is a hint
        /// to the client that it is well-connected to the server in terms of speed.
        /// </summary>
        DS_CLOSEST_FLAG = 0x00000080,

        /// <summary>
        /// Indicates that the server is not an RODC. As described in [MS-ADTS] section 3.1.1.1.9,
        /// all NC replicas hosted on an RODC do not accept originating updates.
        /// </summary>
        DS_WRITABLE_FLAG = 0x00000100,

        /// <summary>
        /// The server is a reliable time server.
        /// </summary>
        DS_GOOD_TIMESERV_FLAG = 0x00000200,

        /// <summary>
        /// The NC is an application NC.
        /// </summary>
        DS_NDNC_FLAG = 0x00000400,

        /// <summary>
        /// The server is an RODC.
        /// </summary>
        DS_SELECT_SECRET_DOMAIN_6_FLAG = 0x00000800,

        /// <summary>
        /// The server is a writable DC, not running Windows 2000 Server or Windows Server 2003.
        /// </summary>
        DS_FULL_SECRET_DOMAIN_6_FLAG = 0x00001000,

        /// <summary>
        /// The Active Directory Web Service, as specified in [MS-ADDM],
        /// is present on the server.
        /// </summary>
        DS_WS_FLAG = 0x00002000,

        /// <summary>
        /// The server is not running Windows 2000, Windows Server 2003,
        /// Windows Server 2008, or Windows Server 2008 R2.
        /// </summary>
        DS_DS_8_FLAG = 0x00004000,

        /// <summary>
        /// The server is not running Windows 2000, Windows Server2003,
        /// Windows Server 2008, Windows Server 2008 R2, or Windows Server 2012.
        /// </summary>
        DS_DS_9_FLAG = 0x00008000,

        /// <summary>
        /// The server has a DNS name.
        /// </summary>
        DS_DNS_CONTROLLER_FLAG = 0x20000000,

        /// <summary>
        /// The NC is a default NC.
        /// </summary>
        DS_DNS_DOMAIN_FLAG = 0x40000000,

        /// <summary>
        /// The NC is the forest root
        /// </summary>
        DS_DNS_FOREST_FLAG = 0x80000000,
    }

    /// <summary>
    /// Class to decode CLDAP ping response.
    /// </summary>
    internal static class NetlogonResponseDecoder
    {
        /// <summary>
        /// Decode ping response object from buffer.
        /// </summary>
        /// <param name="buf">Data buffer returned from server.</param>
        /// <returns>Decoded ping response object.</returns>
        /// <exception cref="CldapException">Error parsing the data buffer.</exception>
        public static PingResponse Decode(byte[] buf)
        {
            var header = DecodeStruct<NETLOGON_SAM_LOGON_RESPONSE_EX_HEADER>(buf);
            var strings = DecodeCompressedStrings(buf);
            var footer =
                DecodeStruct<NETLOGON_SAM_LOGON_RESPONSE_EX_FOOTER>(
                    buf.Skip(buf.Length - Marshal.SizeOf(typeof(NETLOGON_SAM_LOGON_RESPONSE_EX_FOOTER))).ToArray());
            var serverInformation =
                new PingResponse(
                    new Guid(header.DomainGuid.A, header.DomainGuid.B, header.DomainGuid.C, header.DomainGuid.D),
                    header.Flags,
                    strings);
            if ((footer.NtVersion & 0x04) == 0 || footer.LmNtToken != 0xffff || footer.Lm20Token != 0xffff)
            {
                throw new CldapException(
                    $"CLDAP ping response contained unexpected final values {footer.NtVersion}, {footer.LmNtToken}, {footer.Lm20Token}");
            }

            return serverInformation;
        }

        private static T DecodeStruct<T>(byte[] buf)
        {
            var objPtr = IntPtr.Zero;
            try
            {
                var objSz = Marshal.SizeOf(typeof(T));
                objPtr = Marshal.AllocHGlobal(objSz);
                Marshal.Copy(buf, 0, objPtr, objSz);
                var structure = (T)Marshal.PtrToStructure(objPtr, typeof(T));
                return structure;
            }
            catch
            {
                return default;
            }
            finally
            {
                Marshal.FreeHGlobal(objPtr);
            }
        }

        private static string[] DecodeCompressedStrings(byte[] buf)
        {
            var strings = new List<string>();
            var startIndex = Marshal.SizeOf(typeof(NETLOGON_SAM_LOGON_RESPONSE_EX_HEADER));
            var endIndex = buf.Length - Marshal.SizeOf(typeof(NETLOGON_SAM_LOGON_RESPONSE_EX_FOOTER));
            var labels = new SortedList<int, string>();
            string str = null;
            for (; startIndex < endIndex; startIndex++)
            {
                if (buf[startIndex] == 0x00)
                {
                    strings.Add(str);
                    str = null;
                    labels.Add(startIndex, null);
                }
                else if ((buf[startIndex] & 0xc0) == 0xc0)
                {
                    // 1100 0000, Bit-8 and Bit-7 set means pointer
                    if (startIndex + 1 >= endIndex)
                    {
                        throw new CldapException("Bad encoding of RFC 1035 string pointer");
                    }

                    var ptr = (int)buf[startIndex + 1];
                    var labelIndex = labels.IndexOfKey(ptr);
                    if (labelIndex == -1)
                    {
                        throw new CldapException("Bad encoding of value of RFC 1035 string pointer");
                    }

                    var ptrStr = labels
                        .Skip(labelIndex)
                        .TakeWhile(label => label.Value != null)
                        .Aggregate<KeyValuePair<int, string>, string>(
                            null,
                            (current, label) => current == null ? label.Value : current + "." + label.Value);
                    str = str == null ? ptrStr : str + "." + ptrStr;
                    strings.Add(str);
                    str = null;
                    startIndex++; // Just skip ptr marker, the loop condition will do the rest
                }
                else
                {
                    var sz = (int)buf[startIndex];
                    if (startIndex + 1 + sz >= endIndex)
                    {
                        throw new CldapException("Bad encoding of RFC 1035 string label");
                    }

                    var label = Encoding.UTF8.GetString(buf.Skip(startIndex + 1).Take(sz).ToArray());
                    labels.Add(startIndex, label);
                    str = str == null ? label : str + "." + label;
                    startIndex += sz; // just skip label length, the loop condition will do the rest
                }
            }

            return strings.ToArray();
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct GUID
        {
            public int A;
            public short B;
            public short C;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
            public byte[] D;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct NETLOGON_SAM_LOGON_RESPONSE_EX_HEADER
        {
            public Opcode Opcode;
            public ushort Sbz;
            public uint Flags;
            public GUID DomainGuid;
        }

        /* RFC 1035 compressed strings go between header and footer
           See RFC 1035 4.1.4
           See [MS-ADTS] 6.3.7
            DnsForestName
            DnsDomainName
            DnsHostName
            NetbiosDomainName
            ComputerName
            UserName
            DcSiteName
            ClientSiteName
            NextClosestSiteName (Included only if NETLOGON_NT_VERSION_WITH_CLOSEST_SITE is used) */

        /// <summary />
        [StructLayout(LayoutKind.Sequential)]
        private struct NETLOGON_SAM_LOGON_RESPONSE_EX_FOOTER
        {
            public uint NtVersion;
            public ushort LmNtToken;
            public ushort Lm20Token;
        }
    }
}
