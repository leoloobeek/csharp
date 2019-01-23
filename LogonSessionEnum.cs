using System;
using System.Runtime.InteropServices;
using System.Security.Principal;

// Built from https://www.codeproject.com/Articles/18179/Using-the-Local-Security-Authority-to-Enumerate-Us
// and Pinvoke.net <3

namespace LogonSessionEnum
{
    class Program
    {
        static void Main(string[] args)
        {
            int infoLength = 0;
            IntPtr tokenInformation;

            // since TokenInformation is a buffer, we need to call GetTokenInformation twice, first time to get the length for the buffer
            GetTokenInformation(WindowsIdentity.GetCurrent().Token, TOKEN_INFORMATION_CLASS.TokenStatistics, IntPtr.Zero, 0, out infoLength);
            tokenInformation = Marshal.AllocHGlobal(infoLength);
            GetTokenInformation(System.Security.Principal.WindowsIdentity.GetCurrent().Token, TOKEN_INFORMATION_CLASS.TokenStatistics, tokenInformation, infoLength, out infoLength);
            TOKEN_STATISTICS tokenStatistics = (TOKEN_STATISTICS)Marshal.PtrToStructure(tokenInformation, typeof(TOKEN_STATISTICS));

            EnumerateLogonSessions(tokenStatistics.AuthenticationId.LowPart);
            Marshal.FreeHGlobal(tokenInformation);
        }

        static void EnumerateLogonSessions(uint currentLUID)
        {
            UInt64 count;
            IntPtr pLuid;
            IntPtr pLuidList = IntPtr.Zero;
            uint AccessDenied = 0xc0000022;
            DateTime systime = new DateTime(1601, 1, 1, 0, 0, 0, 0);

            if (LsaEnumerateLogonSessions(out count, out pLuidList) != 0)
            {
                Console.WriteLine("[!] Error running LsaEnumerateLogonSessions()");
                Console.ReadLine();

                return;
            }

            // Sets pLuid to the first LUID structure in the list
            pLuid = pLuidList;

            // count stores number of LUIDs in the list
            for (ulong idx = 0; idx < count; idx++)
            {
                IntPtr pSessionData;
                uint result = LsaGetLogonSessionData(pLuid, out pSessionData);
                if (result != 0)
                {
                    if (result == AccessDenied)
                    {
                        Console.WriteLine("[!] Access denied enumerating LogonId {0:X2}", pLuid);
                    }
                    else
                    {
                        Console.WriteLine("[!] Unknown error accessing session data for LogonId {0:X2}: {1}", pLuid, result);
                    }
                    continue;
                }

                SECURITY_LOGON_SESSION_DATA sessionData = (SECURITY_LOGON_SESSION_DATA)Marshal.PtrToStructure(pSessionData, typeof(SECURITY_LOGON_SESSION_DATA));

                if (pSessionData == IntPtr.Zero)
                {
                    // Not a valid logon session
                    continue;
                }

                // Marshal our data
                String username = Marshal.PtrToStringUni(sessionData.Username.buffer).Trim();
                String domain = Marshal.PtrToStringUni(sessionData.DnsDomainName.buffer).Trim();
                String sid = new System.Security.Principal.SecurityIdentifier(sessionData.PSiD).Value;
                String package = Marshal.PtrToStringUni(sessionData.AuthenticationPackage.buffer).Trim();
                SECURITY_LOGON_TYPE logonType = (SECURITY_LOGON_TYPE)sessionData.LogonType;
                DateTime logonTime = systime.AddTicks((long)sessionData.LoginTime);

                if (domain == "")
                {
                    domain = Marshal.PtrToStringUni(sessionData.LoginDomain.buffer).Trim();
                }

                // Write our data
                Console.WriteLine();
                if (currentLUID == sessionData.LoginID.LowPart)
                {
                    Console.WriteLine("***********Current Session***********");
                }
                Console.WriteLine("LogonID (LUID):     {0}", sessionData.LoginID.LowPart);
                Console.WriteLine("User:               {0}\\{1}", domain, username);
                Console.WriteLine("SID:                {0}", sid);
                Console.WriteLine("Auth Package:       {0}", package);
                Console.WriteLine("Logon Type:         {0}", logonType);
                Console.WriteLine("Logon Time:         {0}", logonTime);
                if (currentLUID == sessionData.LoginID.LowPart)
                {
                    Console.WriteLine("*************************************");
                }
                Console.WriteLine();

                // Bunch of typecasts to essentially move our pointer to the next LUID in the list
                pLuid = (IntPtr)((int)pLuid + Marshal.SizeOf(typeof(LUID)));
                LsaFreeReturnBuffer(pSessionData);
            }
            LsaFreeReturnBuffer(pLuid);
            Console.ReadLine();
        }

        [DllImport("Secur32.dll", SetLastError = false)]
        private static extern uint LsaEnumerateLogonSessions(out UInt64 LogonSessionCount, out IntPtr LogonSessionList);

        [DllImport("Secur32.dll", SetLastError = false)]
        private static extern uint LsaGetLogonSessionData(IntPtr luid, out IntPtr ppLogonSessionData);

        [DllImport("secur32.dll", SetLastError = false)]
        private static extern uint LsaFreeReturnBuffer(IntPtr buffer);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool GetTokenInformation(IntPtr TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass, 
            IntPtr TokenInformation, int TokenInformationLength, out int ReturnLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool OpenProcessToken(IntPtr hProcess, UInt32 dwDesiredAccess, out IntPtr hToken);


        enum TOKEN_INFORMATION_CLASS
        {
            TokenUser = 1,
            TokenGroups,
            TokenPrivileges,
            TokenOwner,
            TokenPrimaryGroup,
            TokenDefaultDacl,
            TokenSource,
            TokenType,
            TokenImpersonationLevel,
            TokenStatistics,
            TokenRestrictedSids,
            TokenSessionId,
            TokenGroupsAndPrivileges,
            TokenSessionReference,
            TokenSandBoxInert,
            TokenAuditPolicy,
            TokenOrigin
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct TOKEN_STATISTICS
        {
            public LUID TokenId;
            public LUID AuthenticationId;
            public long ExpirationTime;
            public uint TokenType;
            public uint ImpersonationLevel;
            public uint DynamicCharged;
            public uint DynamicAvailable;
            public uint GroupCount;
            public uint PrivilegeCount;
            public LUID ModifiedId;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct LSA_UNICODE_STRING
        {
            public UInt16 Length;
            public UInt16 MaximumLength;
            public IntPtr buffer;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct LUID
        {
            public UInt32 LowPart;
            public UInt32 HighPart;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct SECURITY_LOGON_SESSION_DATA
        {
            public UInt32 Size;
            public LUID LoginID;
            public LSA_UNICODE_STRING Username;
            public LSA_UNICODE_STRING LoginDomain;
            public LSA_UNICODE_STRING AuthenticationPackage;
            public UInt32 LogonType;
            public UInt32 Session;
            public IntPtr PSiD;
            public UInt64 LoginTime;
            public LSA_UNICODE_STRING LogonServer;
            public LSA_UNICODE_STRING DnsDomainName;
            public LSA_UNICODE_STRING Upn;
        }

        private enum SECURITY_LOGON_TYPE : uint
        {
            Interactive = 2,    //The security principal is logging on interactively. 
            Network,        //The security principal is logging using a network. 
            Batch,          //The logon is for a batch process. 
            Service,        //The logon is for a service account. 
            Proxy,          //Not supported. 
            Unlock,         //The logon is an attempt to unlock a workstation.
            NetworkCleartext,   //The logon is a network logon with cleartext credentials.
            NewCredentials,     // Allows the caller to clone its current token and specify new credentials for outbound connections. 
            RemoteInteractive,  // A terminal server session that is both remote and interactive.
            CachedInteractive,  // Attempt to use the cached credentials without going out across the network.
            CachedRemoteInteractive, // Same as RemoteInteractive, except used internally for auditing purposes.
            CachedUnlock      // The logon is an attempt to unlock a workstation.
        }
    }
}
