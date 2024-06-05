namespace Petrsnd.CldapCore
{
    using System;
    using System.Collections.Generic;
    using System.Text;

    public class PingResponse
    {
        private readonly uint _flags = 0;

        public PingResponse(Guid domainGuid, uint flags, string[] strings)
        {
            _flags = flags;
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

        public override string ToString()
        {
            var stringBuilder = new StringBuilder();
            stringBuilder.AppendLine($"Domain GUID:          {DomainGuid}");
            stringBuilder.AppendLine($"Forest DNS Name:      {DnsForestName}");
            stringBuilder.AppendLine($"Domain DNS Name:      {DnsDomainName}");
            stringBuilder.AppendLine($"NetBIOS Domain Name:  {NetbiosDomainName}");
            stringBuilder.AppendLine($"NetBIOS Server Name:  {NetbiosComputerName}");
            stringBuilder.AppendLine($"Server Site Name:     {DcSiteName}");
            stringBuilder.AppendLine($"Client Site Name:     {ClientSiteName}");
            stringBuilder.AppendLine($"Server Flags:         {Flags}");
            stringBuilder.AppendLine($"WS2003R2+:            {IsWindows2003R2OrAbove}");
            stringBuilder.AppendLine($"WS2008R2+:            {IsWindows2008R2OrAbove}");
            stringBuilder.AppendLine($"WS2012R2+:            {IsWindows2012R2OrAbove}");
            return stringBuilder.ToString();
        }

        public Guid DomainGuid { get; private set; }
        public string DnsForestName { get; set; }
        public string DnsDomainName { get; set; }
        public string DnsHostName { get; set; }
        public string NetbiosDomainName { get; set; }
        public string NetbiosComputerName { get; set; }
        public string DcSiteName { get; set; }
        public string ClientSiteName { get; set; }

        // Server Properties
        public string Flags
        {
            get
            {
                var strings = new List<string>();
                if (IsPrimaryDomainController) strings.Add("PDC");
                if (IsGlobalCatalog) strings.Add("GC");
                if (IsDomainController) strings.Add("DC");
                if (IsLdapServer) strings.Add("LDAP");
                if (IsKeyDistributionCenter) strings.Add("KDC");
                if (IsInClientSite) strings.Add("IN_SITE");
                if (IsWritable) strings.Add("WRITABLE");
                if (IsReadOnly) strings.Add("READ_ONLY");
                if (IsTimeServer) strings.Add("TIME_SERV");
                if (IsGoodTimeServer) strings.Add("GOOD_TIME_SRV");
                if (HasActiveDirectoryWebService) strings.Add("WEB_SERVICE");
                return string.Join(" ", strings);
            }
        }

        private bool CheckFlag(DS_FLAG dsFlag)
        {
            return (_flags & (uint)dsFlag) != 0;
        }
        // The server holds the PDC FSMO role (PdcEmulationMasterRole).
        public bool IsPrimaryDomainController => CheckFlag(DS_FLAG.DS_PDC_FLAG);
        // The server is a GC server and will accept and process GC messages.
        public bool IsGlobalCatalog => CheckFlag(DS_FLAG.DS_GC_FLAG);
        // The server is an LDAP server.
        public bool IsLdapServer => CheckFlag(DS_FLAG.DS_LDAP_FLAG);
        // The server is a DC.
        public bool IsDomainController => CheckFlag(DS_FLAG.DS_DS_FLAG);
        // The server is running the Kerberos Key Distribution Center service.
        public bool IsKeyDistributionCenter => CheckFlag(DS_FLAG.DS_KDC_FLAG);
        // The Win32 Time Service, as specified in [MS-W32T], is present on the server.
        public bool IsTimeServer => CheckFlag(DS_FLAG.DS_TIMESERV_FLAG);
        // The server is in the same site as the client.
        public bool IsInClientSite => CheckFlag(DS_FLAG.DS_CLOSEST_FLAG);
        // Indicates that the server is not an RODC.
        public bool IsWritable => CheckFlag(DS_FLAG.DS_WRITABLE_FLAG);
        // The server is a reliable time server.
        public bool IsGoodTimeServer => CheckFlag(DS_FLAG.DS_GOOD_TIMESERV_FLAG);
        public bool IsApplicationNamingContext => CheckFlag(DS_FLAG.DS_NDNC_FLAG);
        // The server is an RODC.
        public bool IsReadOnly => CheckFlag(DS_FLAG.DS_SELECT_SECRET_DOMAIN_6_FLAG);
        // The Active Directory Web Service, as specified in [MS-ADDM], is present on the server.
        public bool HasActiveDirectoryWebService => CheckFlag(DS_FLAG.DS_WS_FLAG);
        // The server is a writable DC, not running Windows 2000 Server or Windows Server 2003.
        public bool IsWindows2003R2OrAbove => CheckFlag(DS_FLAG.DS_FULL_SECRET_DOMAIN_6_FLAG);
        // The server is not running Windows 2000, Windows Server 2003, Windows Server 2008, or Windows Server 2008 R2.
        public bool IsWindows2008R2OrAbove => CheckFlag(DS_FLAG.DS_DS_8_FLAG);
        // The server is not running Windows 2000, Windows Server 2003, Windows Server 2008, Windows Server 2008 R2, or Windows Server 2012.
        public bool IsWindows2012R2OrAbove => CheckFlag(DS_FLAG.DS_DS_9_FLAG);
        // The server has a DNS name.
        public bool HasDnsName => CheckFlag(DS_FLAG.DS_DNS_CONTROLLER_FLAG);
        // The NC is a default NC.
        public bool IsDefaultNamingContext => CheckFlag(DS_FLAG.DS_DNS_DOMAIN_FLAG);
        // The NC is the forest root
        public bool IsForestNamingContext => CheckFlag(DS_FLAG.DS_DNS_FOREST_FLAG);
    }
}
