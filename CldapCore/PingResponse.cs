// <copyright file="PingResponse.cs" company="petrsnd">
// (c) 2024 Daniel F. Peterson (petrsnd@gmail.com)
// </copyright>
namespace Petrsnd.CldapCore
{
    using System;
    using System.Collections.Generic;
    using System.Text;

    /// <summary>
    /// This class represents a CLDAP ping response.
    /// </summary>
    public class PingResponse
    {
        private readonly uint _flags = 0;

        /// <summary>
        /// Initializes a new instance of the <see cref="PingResponse"/> class.
        /// </summary>
        /// <param name="domainGuid">The GUID of the domain.</param>
        /// <param name="flags">Flags for this naming context.</param>
        /// <param name="strings">Strings parsed from the ping response.</param>
        /// <exception cref="CldapException">Errors in the response encoding.</exception>
        internal PingResponse(Guid domainGuid, uint flags, string[] strings)
        {
            this._flags = flags;
            DomainGuid = domainGuid;
            if (strings.Length < 8)
            {
                throw new CldapException(
                    $"CLDAP ping response contained {strings.Length} RFC 1035 encoded strings instead of expected 8");
            }

            DnsForestName = strings[0];
            DnsDomainName = strings[1];
            DnsHostName = strings[2];
            NetbiosDomainName = strings[3];
            NetbiosComputerName = strings[4];

            // strings[5] is UserName -- not requesting it, comes back null
            DcSiteName = strings[6];
            ClientSiteName = strings[7];
        }

        /// <summary>
        /// The GUID of the domain.
        /// </summary>
        public Guid DomainGuid { get; private set; }

        /// <summary>
        /// The DNS forest name.
        /// </summary>
        public string DnsForestName { get; set; }

        /// <summary>
        /// The DNS domain name.
        /// </summary>
        public string DnsDomainName { get; set; }

        /// <summary>
        /// The DNS server name.
        /// </summary>
        public string DnsHostName { get; set; }

        /// <summary>
        /// The domain NETBIOS name.
        /// </summary>
        public string NetbiosDomainName { get; set; }

        /// <summary>
        /// The server NETBIOS name.
        /// </summary>
        public string NetbiosComputerName { get; set; }

        /// <summary>
        /// The server site anme.
        /// </summary>
        public string DcSiteName { get; set; }

        /// <summary>
        /// The client site name.
        /// </summary>
        public string ClientSiteName { get; set; }

        /// <summary>
        /// A string representation of all CLDAP ping response flags.
        /// </summary>
        public string Flags
        {
            get
            {
                var strings = new List<string>();
                if (IsPrimaryDomainController)
                {
                    strings.Add("PDC");
                }

                if (IsGlobalCatalog)
                {
                    strings.Add("GC");
                }

                if (IsDomainController)
                {
                    strings.Add("DC");
                }

                if (IsLdapServer)
                {
                    strings.Add("LDAP");
                }

                if (IsKeyDistributionCenter)
                {
                    strings.Add("KDC");
                }

                if (IsInClientSite)
                {
                    strings.Add("IN_SITE");
                }

                if (IsWritable)
                {
                    strings.Add("WRITABLE");
                }

                if (IsReadOnly)
                {
                    strings.Add("READ_ONLY");
                }

                if (IsTimeServer)
                {
                    strings.Add("TIME_SERV");
                }

                if (IsGoodTimeServer)
                {
                    strings.Add("GOOD_TIME_SRV");
                }

                if (HasActiveDirectoryWebService)
                {
                    strings.Add("WEB_SERVICE");
                }

                return string.Join(" ", strings);
            }
        }

        /// <summary>
        /// The server holds the PDC FSMO role (PdcEmulationMasterRole).
        /// </summary>
        public bool IsPrimaryDomainController => CheckFlag(DS_FLAG.DS_PDC_FLAG);

        /// <summary>
        /// The server is a global catalog (GC) server and will accept and process GC messages.
        /// </summary>
        public bool IsGlobalCatalog => CheckFlag(DS_FLAG.DS_GC_FLAG);

        /// <summary>
        /// The server is an LDAP server.
        /// </summary>
        public bool IsLdapServer => CheckFlag(DS_FLAG.DS_LDAP_FLAG);

        /// <summary>
        /// The server is a domain controller (DC).
        /// </summary>
        public bool IsDomainController => CheckFlag(DS_FLAG.DS_DS_FLAG);

        /// <summary>
        /// The server is running the Kerberos Key Distribution Center service.
        /// </summary>
        public bool IsKeyDistributionCenter => CheckFlag(DS_FLAG.DS_KDC_FLAG);

        /// <summary>
        /// The Win32 Time Service, as specified in [MS-W32T], is present on the server.
        /// </summary>
        public bool IsTimeServer => CheckFlag(DS_FLAG.DS_TIMESERV_FLAG);

        /// <summary>
        /// The server is in the same site as the client.
        /// </summary>
        public bool IsInClientSite => CheckFlag(DS_FLAG.DS_CLOSEST_FLAG);

        /// <summary>
        /// Indicates that the server is not a read-only domain controller (RODC).
        /// </summary>
        public bool IsWritable => CheckFlag(DS_FLAG.DS_WRITABLE_FLAG);

        /// <summary>
        /// The server is a reliable time server.
        /// </summary>
        public bool IsGoodTimeServer => CheckFlag(DS_FLAG.DS_GOOD_TIMESERV_FLAG);

        /// <summary>
        /// The naming context is an application naming context.
        /// </summary>
        public bool IsApplicationNamingContext => CheckFlag(DS_FLAG.DS_NDNC_FLAG);

        /// <summary>
        /// The server is a read-only domain controller (RODC).
        /// </summary>
        public bool IsReadOnly => CheckFlag(DS_FLAG.DS_SELECT_SECRET_DOMAIN_6_FLAG);

        /// <summary>
        /// The Active Directory Web Service, as specified in [MS-ADDM], is present on the server.
        /// </summary>
        public bool HasActiveDirectoryWebService => CheckFlag(DS_FLAG.DS_WS_FLAG);

        /// <summary>
        /// The server is a writable domain controller (DC), not running Windows 2000 Server or Windows Server 2003.
        /// </summary>
        public bool IsWindows2003R2OrAbove => CheckFlag(DS_FLAG.DS_FULL_SECRET_DOMAIN_6_FLAG);

        /// <summary>
        /// The server is not running Windows 2000, Windows Server 2003, Windows Server 2008, or Windows Server 2008 R2.
        /// </summary>
        public bool IsWindows2008R2OrAbove => CheckFlag(DS_FLAG.DS_DS_8_FLAG);

        /// <summary>
        /// The server is not running Windows 2000, Windows Server 2003, Windows Server 2008, Windows Server 2008 R2, or Windows Server 2012.
        /// </summary>
        public bool IsWindows2012R2OrAbove => CheckFlag(DS_FLAG.DS_DS_9_FLAG);

        /// <summary>
        /// The server has a DNS name.
        /// </summary>
        public bool HasDnsName => CheckFlag(DS_FLAG.DS_DNS_CONTROLLER_FLAG);

        /// <summary>
        /// The naming context is a default naming context.
        /// </summary>
        public bool IsDefaultNamingContext => CheckFlag(DS_FLAG.DS_DNS_DOMAIN_FLAG);

        /// <summary>
        /// The naming context is the forest root.
        /// </summary>
        public bool IsForestNamingContext => CheckFlag(DS_FLAG.DS_DNS_FOREST_FLAG);

        /// <summary>
        /// Returns summary information about a CLDAP ping response.
        /// </summary>
        /// <returns>A string containing a summary of ping response properties.</returns>
        public override string ToString()
        {
            var stringBuilder = new StringBuilder();
            return stringBuilder
                .AppendLine($"Domain GUID:          {DomainGuid}")
                .AppendLine($"Forest DNS Name:      {DnsForestName}")
                .AppendLine($"Domain DNS Name:      {DnsDomainName}")
                .AppendLine($"NetBIOS Domain Name:  {NetbiosDomainName}")
                .AppendLine($"NetBIOS Server Name:  {NetbiosComputerName}")
                .AppendLine($"Server Site Name:     {DcSiteName}")
                .AppendLine($"Client Site Name:     {ClientSiteName}")
                .AppendLine($"Server Flags:         {Flags}")
                .AppendLine($"WS2003R2+:            {IsWindows2003R2OrAbove}")
                .AppendLine($"WS2008R2+:            {IsWindows2008R2OrAbove}")
                .AppendLine($"WS2012R2+:            {IsWindows2012R2OrAbove}")
                .ToString();
        }

        private bool CheckFlag(DS_FLAG dsFlag) => (_flags & (uint)dsFlag) != 0;
    }
}
