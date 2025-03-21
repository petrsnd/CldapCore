# CldapCore
CLDAP library for pinging Active Directory domain controllers to return capabilities and site information.

## NuGet
[CldapCore](https://www.nuget.org/packages/CldapCore) package on nuget.org.

To install CldapCore, run the following command in the [Package Manager Console](https://docs.nuget.org/docs/start-here/using-the-package-manager-console):
```Powershell
PM> Install-Package CldapCore
```

## Sources
There are two projects included in the solution:
- CldapCore -- The simple library for sending CLDAP ping requests and decoding responses.
- CldapTool -- A command-line tool for trying out the library.

## Example
Use the static `Cldap` class to call the `Ping()` method.  Only required parameter is `IpAddress`.
```C#
TODO
```

## Additional Information
CLDAP stands for Connection-less Lightweight Directory Access Protocol.  It is based on LDAP, but it communicates over
UDP rather than TCP.  The CLDAP protocol was originally documented in [RFC1798](https://www.rfc-editor.org/rfc/rfc1798), but it
was not successful on the IETF standards track.  However, Microsoft used it as a simple protocol that Active Directory clients
use to gather information about domain controllers.  Microsoft documents how it is used to locate a domain controller in
[MS-ADOD 3.1.1](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adod/3078ef00-5bfc-4808-be80-c58b9c6cbb76).
Additional information about domain controller location discovery via DNS is found in
[MS-ADTS 6.3.6](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/7fcdce70-5205-44d6-9c3a-260e616a2f04).
Specific details about CLDAP ping are found in
[MS-AdTS 6.3.3](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/895a7744-aff3-4f64-bcfa-f8c05915d2e9).
