# Red Team on Windows — an offensive and detection knowledge compendium

*As of August 2026. Research document: methodology, techniques, tooling, infrastructure, and the detection counterpoint. A sister edition to "Red Team on Linux — an offensive and detection knowledge compendium".*

---

## Executive summary

This compendium organizes the complete offensive (red team) operation path in Windows and Active Directory environments — from reconnaissance and initial access, through host and domain enumeration, privilege escalation, persistence, endpoint detection evasion, credential access, lateral movement, up to domain dominance, Command & Control infrastructure, and actions on objective. The document is a sister edition of the Linux compendium and preserves its architecture: each stage is mapped to MITRE ATT&CK tactics and paired with a detection counterpoint, because a red team operation is judged by whether the defense was able to detect it — not by achieving the objective alone [^124^]. It reflects the freshest state of knowledge: the Potato attack family together with variants that work on fully patched systems, and EDR evasion techniques from direct syscalls to BYOVD [^144^][^164^]. Alongside them it covers modern incarnations of NTLM relay (CVE-2025-33073), AD CS exploitation (ESC1–ESC8), and detection telemetry built on Sysmon, the Security Log, and ETW [^184^][^186^].

Key synthetic conclusions. First, **Windows is above all a game about identity**: Active Directory is the central authentication system of most organizations, and its compromise means the compromise of the entire enterprise [^127^]. Microsoft reports that 78% of human-operated attacks end with the compromise of a domain controller, while Akamai research shows that in 91% of examined environments ordinary users already have sufficient privileges today to escalate to Domain Admin [^120^]. Second, **attackers don't "break in" — they log in**: 82% of detections in 2025 were malware-free, and the average breakout time fell to 29 minutes (fastest: 27 seconds), which means that classic signature-based detection is structurally too late [^200^]. Third, **privilege escalation on a Windows host is mostly misconfiguration, not exploitation**: SeImpersonatePrivilege on service accounts, services with weak ACLs, unquoted paths, and DLLs loaded from writable directories dominate over kernel bugs [^141^][^152^]. Fourth, **detection is possible and well documented**: Event ID 4662 with replication GUIDs detects DCSync, and 4769 with RC4 encryption detects Kerberoasting [^175^][^180^]. Sysmon Event ID 10 logs access to LSASS memory — the problem is not a lack of signals, but that most organizations do not collect them [^190^].

---

## Legal and ethical disclaimer

All techniques described in this document serve exclusively educational purposes, authorized security testing, and detection engineering. Running offensive tools on systems without the explicit, written consent of the owner constitutes a crime (in Poland, among others, Articles 267–269 of the Penal Code). Professional red team operations take place within formal Rules of Engagement defining scope, permitted techniques, timeframes, and deconfliction procedures [^124^]. Particular care applies to destructive or hard-to-reverse techniques (ACL changes in the domain, RBCD, shadow credentials): operator practice emphasizes the obligation of full cleanup — removing machine accounts, cleaning delegation attributes, reverting entries [^126^]. The author assumes no liability for misuse.

---

## 1. Fundamentals of Red Team operations on Windows

### 1.1 Why Windows and AD are a separate discipline

A red team operation in a Windows environment differs fundamentally from a Linux one: the strategic objective is almost always **Active Directory**, the enterprise's central identity system, whose takeover grants control over all users, systems, and data [^127^]. The practical consequence is that a large part of Windows tradecraft does not concern exploits, but the abuse of legitimate authentication mechanisms (Kerberos, NTLM), trust relationships, and directory misconfigurations — and CrowdStrike confirms this macroscopically: 82% of detections in 2025 concerned malware-free activity carried out with valid credentials and trusted identity flows [^200^]. This is why MITRE ATT&CK introduces the common language here: over 200 techniques and hundreds of Enterprise sub-techniques, with the Defense Evasion tactic among the most frequently observed in real intrusions [^121^][^125^].

The second distinguishing feature is speed. The average breakout time (from initial access to lateral movement) fell in 2025 to **29 minutes** — 65% faster than the year before — and the fastest observed was 27 seconds [^200^]. For the operator this means pressure on preparation: domain enumeration, credential collection, and lateral movement must be drilled to the level of reflex. For the defender — that the reaction window is measured in minutes, so detection must be automated, not analytical [^201^].

### 1.2 The canonical Active Directory attack chain

A realistic attack chain on AD has five phases: **foothold** (phishing, password spraying, vulnerability), **domain reconnaissance** (relationship mapping with BloodHound), **credential collection** (LSASS, Kerberoasting, DPAPI), **escalation along attack paths** (ACLs, delegations, AD CS), and **domain dominance** (DCSync, ticket forgery, GPO) [^120^]. A model example from 2025: the Scattered Spider group called the Marks & Spencer helpdesk, impersonating an employee, and convinced the agent to reset credentials — from this single foothold it traversed the full chain all the way to stealing the entire AD database; online sales were down for five days, and the share price fell by more than £500 million [^120^]. The entry point was not a zero-day — it was a telephone and a textbook attack path [^120^].

![The canonical Active Directory attack chain](assets-rt-windows/wfig1-lancuch-ad.png)

The key methodological consequence: the attacker follows a predictable path reconnaissance → enumeration → credentials → escalation, and breaking the chain at any point stops the attack [^118^]. This is why the "assume breach" tactic and layered detection — on credentials, on replication, on tickets — are more effective than hardening the perimeter alone. The most common foothold is not exploits, but valid credentials and trusted identity flows [^200^].

### 1.3 OPSEC on the Windows endpoint: MOTW, AMSI, EDR

The operator on Windows works in the most instrumented ecosystem in the world: AMSI scans scripts before execution, ETW delivers behavioral telemetry, Defender and EDRs hook userland APIs, and Sysmon (if deployed) sees processes, network, registry, and memory access [^163^][^199^]. Already at the payload delivery stage the **Mark of the Web** comes into play — the zone identifier (Zone.Identifier) attached to files from the browser/email, which triggers Protected View and macro blocks; operational bypasses include files from trusted locations, internal shares (local files have no MOTW), formats not marked with MOTW (historically OneNote, ISO, VHD), or HTML smuggling [^130^]. A professional operator course (e.g. SANS SEC665) teaches initial access through file format abuse, DLL side-loading, signed payloads, and AiTM phishing bypassing MFA via session theft — always with an analysis of detection trade-offs [^123^].

The overriding OPSEC principle remains identical to the Linux world: footprint minimization (in-memory execution, BOFs instead of fork&run, avoiding writing to disk), infrastructure segregation, a slow tempo, and the awareness that every tool has a detection profile — WinPEAS is "loud but complete", Seatbelt offers better OPSEC, and a SharpHound ingest generates a recognizable pattern of LDAP and RPC queries [^132^][^140^]. The operator selects the tool for the target's defensive profile, not for convenience.

---

## 2. Reconnaissance and initial access (TA0043, TA0001)

### 2.1 External reconnaissance and initial domain enumeration

External reconnaissance covers OSINT (domain registries, certificates, Google dorks, social media, credential leaks) and surface mapping: VPNs, RDP gateways, web panels, mail services [^126^]. On the internal side, even before obtaining credentials, the operator identifies the domain and domain controllers through DNS (`nslookup -type=SRV _ldap._tcp.dc._msdcs.target.local`), enumerates SMB shares anonymously, and scans LDAP/Kerberos ports — this alone often reveals the topology and host naming conventions [^126^]. Password spraying against externally exposed services (OWA, VPN, Entra ID) remains one of the most effective vectors — a single password of the "Season2026!" type tested against all accounts bypasses lockout policies that would stop brute force [^126^].

With a valid domain account — even the lowest-privileged one — the enumeration surface opens up dramatically: by default all authenticated users can query LDAP for almost the entire directory content, including users, groups, computers, ACLs, and trust relationships [^131^][^133^]. This is a fundamental asymmetry of AD: the directory is readable by everyone, and permissions cannot in practice be reliably audited manually — attack paths can therefore only be removed, not "hidden" [^122^].

### 2.2 Initial access vectors: phishing, documents, HTML smuggling

The dominant initial access vector remains phishing with an executable payload: VBA macros, remote template injection, HTML smuggling (assembling the file on the browser side, beyond proxy inspection), shortcut files, and archives bypassing MOTW [^130^]. CrowdStrike notes an explosion of the social-engineering subsection: a 563% increase in incidents with fake CAPTCHAs (ClickFix — the victim pastes a malicious PowerShell command themselves) and a 141% increase in spam [^200^]. In a campaign detected by Fortinet, a modified Havoc Demon agent was delivered precisely through social engineering, and C2 was tunneled through the Microsoft Graph API and SharePoint — legitimate services as a control channel [^219^].

Access through vulnerabilities and access brokers constitutes a parallel current: a 42% increase in zero-days exploited before publication, systematic targeting of edge devices (VPNs, firewalls), and an access broker market selling ready-made footholds to ransomware operators [^200^][^209^]. From the perspective of red team operation planning, the initial access vector is selected to match the profile of the adversary being emulated — and to the ROE, which determines whether social engineering is in scope [^124^].

---

## 3. Post-compromise enumeration (TA0007)

### 3.1 Host enumeration: WinPEAS, Seatbelt, PowerUp

On a single host the privesc checklist is well industrialized: **WinPEAS** (from the PEASS-ng family) performs a broad audit — credentials in the registry and files, service permissions, scheduled tasks, MSI installers, missing patches — color-coding results by exploitation probability [^136^][^132^]. **Seatbelt** (GhostPack) runs an in-depth "security survey" of the host: defensive settings, tokens, UAC, LAPS, Credential Guard, logged-on users, interesting files — and is preferred in covert operations because it is quieter than WinPEAS [^132^]. **PowerUp/SharpUp** target specific service errors (binpath, ACLs, unquoted paths) with automatic weaponization functions, while **Watson/Sherlock** match missing hotfixes to public kernel exploits [^152^][^132^]. Recommended workflow: WinPEAS for broad reconnaissance → Watson for the kernel → Seatbelt for targeted checks → PowerUp wherever a vector has been found [^132^].

Manual checks remain the canon, because every automation has a signature: `whoami /priv` (SeImpersonate? SeDebug?), `wmic service get name,pathname,startmode` with filters for unquoted paths, `accesschk.exe -uwcqv "Authenticated Users" *` for service permissions, `icacls` on service binaries, registry queries for AlwaysInstallElevated and AutoRuns, `schtasks /query /fo LIST /v`, `cmdkey /list`, `findstr /si password *.txt *.ini *.config`, and a review of unattend files [^152^]. Also valuable are Group Policy files with passwords (the historical cpassword in GPP), logon scripts on SYSVOL, and shares with configuration files [^128^].

### 3.2 Domain enumeration: PowerView and native modules

**PowerView** (PowerSploit) is the standard for AD enumeration from an ordinary user's position — it requires neither administrative privileges nor RSAT installation, because it uses AD PowerShell hooks and the Win32 API [^134^][^133^]. The canonical set: `Get-NetDomain`/`Get-NetForest` (environment boundaries), `Get-NetDomainController` (high-value targets), `Get-NetUser` filtered by `pwdlastset`, SPNs (`Get-NetUser -SPN` → Kerberoasting candidates), `Get-DomainGroupMember "Domain Admins" -Recurse`, `Invoke-ShareFinder` and `Find-InterestingDomainShareFile` (shares with secrets), `Get-ObjectAcl` (dangerous rights: GenericAll, GenericWrite, WriteDacl, WriteOwner, ForceChangePassword), `Get-DomainTrustMapping` (trust map), and `Find-LocalAdminAccess` and `Test-AdminAccess` (where I have admin) [^138^][^135^]. Hunting for passwords in the Description field (`Find-UserField -SearchField Description -SearchTerm "pass"`) is a classic that still delivers results [^137^].

Domain enumeration OPSEC is a game about the query pattern: mass LDAP queries with unusual filters, recursive group resolution, and session scanning across all hosts create a signature detectable by identity detection solutions and good SIEM rules (a sudden spike in directory queries from a single account) [^120^][^140^]. The operator weighs the tempo, uses targeted attributes instead of `-Properties *`, and prefers single-pass collectors.

### 3.3 BloodHound and SharpHound: the graph as an operations map

**BloodHound** turns raw enumeration into a relationship graph — users, groups, computers, GPOs, sessions, and ACLs as nodes and edges — and answers the question no flat list can: what is the **shortest path from my account to Domain Admin** [^118^][^119^]. The **SharpHound** collector (C#, with PowerShell/Python/Rust variants) gathers data via signed LDAP queries to DCs and RPC/SMB to hosts (local groups, sessions) — in `-c All` mode, for in-memory execution from an implant [^131^][^140^]. The predefined queries every operation starts with: Shortest Paths to Domain Admins, Principals with DCSync Rights, AS-REP Roastable Users, Kerberoastable Members of High Value Groups, and Shortest Paths from Owned Principals [^119^].

BloodHound is an equally valuable weapon for defenders. SpecterOps shows that even a "small" environment with a thousand endpoints usually has millions of attack paths — so fixing a single path flagged in a red team report resembles closing one side street on a route from Seattle to New York; only systematic path management (Attack Path Management) and removing the highest-throughput nodes is effective [^122^]. Typical fixes: removing unnecessary group nesting in DA, auditing ACLs (GenericAll/WriteDacl/WriteOwner without justification), disabling unconstrained delegation, administrative tiering, LAPS, and correcting DONT_REQ_PREAUTH flags [^119^]. Detecting SharpHound itself is a separate topic: the characteristic LDAP+RPC+SMB pattern ending with a ZIP export is recognizable — hence covert operations use collection stretched over time or limited methods [^140^].

| Tool | Layer | Privileges | Key advantage | Detection signature |
|---|---|---|---|---|
| WinPEAS | host | user | hundreds of checks, prioritization [^136^] | loud, series of registry/service reads [^132^] |
| Seatbelt | host | user | defensive posture survey, better OPSEC [^132^] | moderate |
| PowerUp/SharpUp | host | user | auto-exploitation of service errors [^152^] | AMSI (PowerShell), known signatures |
| Watson | host | user | matching CVEs to the build [^132^] | low |
| PowerView | domain | domain user | full AD enumeration without RSAT [^134^] | LDAP patterns, AMSI |
| SharpHound | domain | domain user | attack path graph [^131^] | LDAP+RPC+SMB+ZIP [^140^] |
| NetExec (nxc) | network | varies | spraying, Pwn3d! validation, modules [^118^] | SMB/RPC patterns, network logons |

---

## 4. Privilege escalation (TA0004)

### 4.1 The Potato family: SeImpersonatePrivilege as a shortcut to SYSTEM

The **SeImpersonatePrivilege** privilege — granted by default to service accounts (IIS, MSSQL, and derivatives) — allows a process to impersonate a client; the Potato attack family turns this mechanism into full escalation by forcing a highly privileged component (RPC/DCOM service, EFSRPC, Print Spooler) to authenticate to a spoofed endpoint, then capturing and impersonating its SYSTEM token [^141^][^144^]. The family's evolution is a story of an arms race: HotPotato (2016) via NTLM relay from HTTP to SMB, Rotten/JuicyPotato with RPC CLSID abstraction, RoguePotato with the OXID resolver on an alternate port, PrintSpoofer via Print Spooler, SweetPotato as the unification, GodPotato on Server 2012–2022, and subsequent variants (LocalPotato, EfsPotato, RemotePotato) exploring new authentication coercion interfaces [^141^]. The latest incarnations (the CoercedPotato line) were demonstrated on then-fully-patched Windows 11 and Server 2025 — confirming that "Potato selection" remains a live operator exercise [^144^].

Detection: unusual child processes of services (cmd/powershell as a child of `spoolsv.exe`, `svchost.exe`), token creation by service accounts, service creation events (7045) right after authentications from an IIS/MSSQL account [^141^]. Mitigations include disabling unnecessary coercion services (Print Spooler on servers without printing), limiting accounts with SeImpersonate/SeAssignPrimaryToken, and system updates patching successive variants [^144^].

![Evolution of the Potato attack family](assets-rt-windows/wfig2-potato.png)

### 4.2 Misconfigurations of services, the registry, and installers

The most common practical escalation axis is **Windows services**: when an ordinary user has modification rights to a service configuration (SERVICE_CHANGE_CONFIG via `sc config binpath=`) or to its binary (FILE_WRITE_DATA in the service directory), restarting the service runs the attacker's code as SYSTEM [^152^]. The **unquoted service path** variant exploits the fact that a path like `C:\Program Files\App Name\service.exe` without quotes is resolved iteratively — it suffices to drop a malicious `App.exe` into `C:\Program Files\` if the directory is writable [^152^]. Analogous effects come from DLL hijacking in writable directories of applications running as SYSTEM and from overwriting scheduled-task binaries [^158^].

In the registry the key items are: **AlwaysInstallElevated** (both HKLM and HKCU keys set to 1 → any MSI installed as SYSTEM, weaponized e.g. via `msfvenom -f msi` or `msiexec /i`), AutoRuns pointing at writable files, Image File Execution Options keys with writable Debuggers, and credentials in keys such as `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon` (AutoAdminLogon) [^152^]. Scheduled tasks, shares with service binaries, unattend files with passwords, saved credentials (`cmdkey /list`), and installer directories complete the checklist [^152^].

### 4.3 UAC bypasses and kernel exploits

**UAC is not a security boundary** — it is a convenience mechanism — but bypassing it is a required step on the way from medium integrity to high/system: the UACME catalog maintains dozens of methods, the best known being fodhelper/eventvwr (hijacking HKCU `ms-settings` keys), autoelevating COM (CMSTPLUA), DLL side-loading into auto-elevating system binaries, and computerdefaults; all operate from HKCU, so they do not require writing to protected locations [^156^][^152^]. Detection: Sysmon EID 12/13 (registry events in `shell\open\command` paths), auto-elevating binaries launched from unusual directories, parent-child relationships (fodhelper → cmd) [^199^][^202^].

Kernel exploits are a last resort — loud, risky for stability, but effective when the target is unpatched: matching via `systeminfo` and Watson/Sherlock [^152^]. The current landscape includes **CVE-2025-62215** (Windows Kernel, race condition → SYSTEM, entered the KEV catalog after in-the-wild exploitation and was patched in the November Patch Tuesday) [^146^][^150^]. Fresh entries from 2026 are **CVE-2026-40369** (Win32k) and **CVE-2026-24289** — a constant stream of kernel EoPs keeps pressure on the patching window [^142^][^143^]. In red team operations kernel exploits are used exceptionally — preference goes to misconfigurations and identity abuse, because they are quieter and reproducible [^118^].

---

## 5. Persistence (TA0003)

### 5.1 Host-based mechanisms

The persistence taxonomy on Windows is broad: **Run/RunOnce keys** (HKLM/HKCU, including `Winlogon\Userinit`, Image File Execution Options with a Debugger), **scheduled tasks** (`schtasks /create /sc onlogon`, highest-privilege variants), **services** (`sc create` / binpath modification), **WMI event subscription** (the EventFilter→Consumer→Binding triplet, fileless and hard to audit), **DLL search order hijacking / COM hijacking** (HKCU over HKLM in COM classes), and **local/backdoor accounts** [^160^][^158^]. In the domain, directory-based vectors are added: AdminSDHolder (inheritance of malicious ACEs onto protected groups), GPO (policy modification = code execution on hundreds of hosts), SIDHistory injection, and skeleton keys (Skeleton Key on the DC) [^128^][^120^].

Stealth persistence is an art of its own: timestomping binaries, names imitating system components, legitimate signatures via side-loading signed binaries, storing payloads in ADS/registry, and fileless variants (WMI, COM) minimizing disk artifacts [^160^]. Detection relies on Sysmon EID 12–14 (registry), events 7045/4697 (services), 4698/4702 (tasks), 5861 (WMI consumers), baselining AutoRuns (the Sysinternals tool), and periodic comparisons against a golden image [^199^][^160^].

### 5.2 Identity as persistence: Kerberos tickets

In an AD environment the most durable form of persistence is **forged credentials**: **Golden Ticket** (a TGT signed with the stolen krbtgt hash — valid by default for up to 10 years, independent of the DC), **Silver Ticket** (a service TGS signed with the service account's hash — requires no contact with the DC after forging), and **Diamond Ticket** (a legitimately obtained TGT whose fields are modified before re-signing — more cryptographically consistent and quieter than golden) [^155^][^159^]. A Golden Ticket survives even a password change of the compromised user; it forces a double reset of the krbtgt password — twice, with an interval for replication and ticket expiry, because AD stores the two most recent hashes [^120^].

Detecting forged tickets is inconsistency analysis: a Golden Ticket often breaks sensible values (lifetimes, PAC), a Silver Ticket generates no 4768/4769 events on the DC (no AS/TGS exchange) — only service logons on the target host are visible; a Diamond Ticket may be quieter because it preserves the legitimate flow [^153^][^120^]. 4769 events with unusual accounts, ten-year ticket lifetimes, and missing protocol steps are signals that should be in the SIEM of every organization monitoring DCs [^157^].

| Mechanism | Scope | Durability | Key detection |
|---|---|---|---|
| Run keys / IFEO | host | until removed | Sysmon 12–14, AutoRuns diff [^160^] |
| Scheduled tasks | host | until removed | 4698/4702, Sysmon 1 (schtasks) [^199^] |
| Services | host | until removed | 7045/4697 [^160^] |
| WMI subscription | host | fileless | 5861, audit of root\subscription [^160^] |
| COM/DLL hijack | host | until removed | Sysmon 7/12–14, AppLocker/WDAC [^158^] |
| AdminSDHolder / GPO | domain | inherited | 5136 (attribute changes), SD audit [^128^] |
| Golden/Diamond Ticket | domain | until krbtgt reset ×2 | 4768/4769/4624 inconsistencies [^154^] |
| Silver Ticket | service | until account password reset | missing 4769 with service logons [^159^] |
| Skeleton Key | DC | until restart/patch | 7045 on the domain controller [^120^] |

---

## 6. Endpoint detection evasion (TA0005)

### 6.1 AMSI and ETW: blinding the sensors

**AMSI** (Antimalware Scan Interface) intercepts PowerShell/JScript/VBA scripts before execution and passes them to the scanner; classic bypasses include an in-memory patch of the `AmsiScanBuffer` function in `amsi.dll` (overwriting the prologue so it returns AMSI_RESULT_CLEAN), forcing initialization errors, and — increasingly — avoiding managed code altogether (BOFs, native PEs) instead of fighting the scripting engine [^163^][^172^]. **ETW** (Event Tracing for Windows) feeds Defender and EDR telemetry; bypasses include patching `EtwEventWrite`, disabling providers inside the implant process, and running in processes the EDR does not instrument [^164^]. Both mechanisms are now protected by tamper protection and PPL, so patching is mostly possible only after escalation or within one's own process — and in itself generates telemetry (suspicious access to system modules is seen by Sysmon and EDRs) [^199^][^164^].

### 6.2 Process injection: taxonomy and signatures

The injection taxonomy covers: **classic** (OpenProcess→VirtualAllocEx→WriteProcessMemory→CreateRemoteThread), **DLL injection** (LoadLibrary via remote thread), **process hollowing** (creating a suspended process, replacing the image, resuming), **APC injection** (including EarlyBird on suspended threads), **AtomBombing** (atom tables), **thread execution hijacking**, and variants such as **module stomping** and **phantom DLL hollowing** [^162^][^161^]. Every variation is an attempt to avoid Sysmon rules: **EID 8** (CreateRemoteThread) sees classic injections, **EID 10** (ProcessAccess) sees opening a process with memory-write access masks — which is why modern tradecraft prefers syscalls, section mappings, and early phases of the process lifecycle, where telemetry is sparser [^199^][^171^].

### 6.3 Direct and indirect syscalls: going below the hooks

EDRs hook `ntdll.dll` functions in userland to see a process's system calls; the offensive answer is **direct syscalls** — executing the `syscall` instruction directly from the implant's memory with a hand-set SSN number (SysWhispers and successors generate stubs for a specific system version), which bypasses ntdll hooks [^165^][^170^]. The problem: static SSNs break with system updates, and jumping to `syscall` from outside ntdll can be an anomaly. **Indirect syscalls** (Hell's Gate, Halo's Gate, Tartarus Gate) solve this by finding a hook-free `syscall; ret` fragment inside ntdll and jumping to it — the call stack then looks legitimate [^164^][^165^]. EDR counter-detection includes call stack analysis (ETW-TI telemetry), inspecting memory of sleeping threads, and detecting sleep obfuscation (**Ekko**, **FOLIAGE** — encrypting the implant's memory during sleep to fool memory scans) [^168^][^166^].

### 6.4 BYOVD, BYOI, and disabling EDR

The heaviest escalation step in tradecraft is disabling the sensor itself: **BYOVD** (Bring Your Own Vulnerable Driver) installs a legitimately signed but vulnerable driver and through it kills EDR processes/callbacks from the kernel — the **LOLDrivers** catalog indexes hundreds of such drivers, and ransomware groups routinely deploy dedicated "EDR killers" [^209^][^168^]. **BYOI** (Bring Your Own Installer) leverages legitimate administrative tools — installers and remote management agents (RMM: AnyDesk, ScreenConnect, Tactical RMM) — as a vehicle for durable access, because they generate legitimate traffic and signed binaries [^209^][^213^]. Detection: loading drivers outside the whitelist (Sysmon EID 6), rules based on the LOLDrivers catalog (hashes/signatures), alerts on RMM installations outside the corporate catalog, and monitoring changes to Defender configuration (EID 5007) and tamper protection disabling [^199^][^209^].

---

## 7. Credential access (TA0006)

### 7.1 LSASS and local secret stores

**LSASS** (`lsass.exe`) holds in memory the secrets of logged-on users (NTLM hashes, Kerberos tickets, passwords in reversible encryption), so dumping it is the shortest route to broad lateral movement: techniques include **Mimikatz** (`sekurlsa::logonpasswords`), dumping via legitimate tools (**comsvcs.dll**: `rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump <pid> <path> full`, **procdump**, Task Manager), and **nanodump** and derivatives with syscalls bypassing hooks [^190^][^196^]. The counter: **LSA Protection (PPL)** enforces signed plugins and blocks access for unsigned processes, while **Credential Guard** (VBS) isolates secrets in a hypervisor enclave [^190^]. The canonical telemetry is Sysmon **EID 10** (ProcessAccess to lsass with characteristic access masks), EID 11 (writing `lsass.dmp`), and ready-made detection rules for LSASS memory dumps — with the caveat that Credential Guard does not protect tickets in use or service accounts outside the isolation scope [^195^][^199^]. Beyond LSASS: **SAM/SECURITY/SYSTEM** (local account hashes, `reg save` or a shadow volume), **LSA secrets** (service account passwords), the **domain logon cache** (MSCASHv2 — not for PtH, but for offline cracking), and the memory of password managers and browsers [^190^].

### 7.2 Kerberoasting, AS-REP roasting

**Kerberoasting** exploits the fact that any authenticated user can request a service ticket (TGS) for any account with an SPN — and a fragment of the TGS is encrypted with a key derived from the service account's password, so it can be cracked offline (Rubeus `kerberoast` → Hashcat `-m 13100` for RC4) [^180^][^120^]. Target enumeration: `Get-NetUser -SPN` (PowerView) or `GetUserSPNs.py` (Impacket) [^138^]. Detection is mature: **EID 4769** with **RC4 (0x17)** encryption where AES (0x12) normally dominates, bursts of requests for many SPNs from one host — one of the highest-signal AD rules, because attackers' tools deliberately request RC4, which is faster to crack [^120^]. **AS-REP roasting** targets accounts with the DONT_REQ_PREAUTH flag: the AS-REP response contains data encrypted with the user's key — cracked offline (`GetNPUsers.py`, Rubeus `asreproast`), with **EID 4768** with pre-authentication type 0 as the detection [^120^]. Defense: long random passwords for service accounts (gMSA), removing DONT_REQ_PREAUTH, monitoring 4768/4769 [^180^].

### 7.3 DCSync: replication as a weapon

**DCSync** simulates a domain controller and, through the replication protocol (MS-DRSR, `DsGetNCChanges`), pulls the hashes of arbitrary accounts — including krbtgt — without logging on to the DC and without dumping NTDS.dit from disk [^173^][^175^]. The required rights are a triplet of extended replication rights on the domain object: **DS-Replication-Get-Changes** (GUID 1131f6aa…), **…-All** (1131f6ad…), and optionally **…-In-Filtered-Set**; by default they are held by Administrators, Domain Admins, Enterprise Admins, and domain controllers — but through faulty ACLs often also by service accounts "for AD backup" [^175^]. Execution: `secretsdump.py 'DOMAIN/user:pass@DC' -just-dc` or `lsadump::dcsync /user:krbtgt` (Mimikatz) [^173^]. The canonical detection: **EID 4662** (Directory Service Access) with the listed GUIDs in the Properties field, generated by a host that **is not a domain controller** — a rule with an extremely low false-positive level, because legitimate replication always comes from a DC [^175^][^120^]. DCSync is the closing chord of most operations: with the krbtgt hash the operator forges Golden Tickets [^154^].

### 7.4 DPAPI and "secrets on the workstation"

**DPAPI** encrypts secrets with a key derived from the user's password (or the machine key) — it protects browser cookies and passwords, Credential Manager credentials, certificate private keys, and configuration files [^178^]. Offensively: **SharpDPAPI**, mimikatz `dpapi::`, and DPAPI BOFs recover masterkeys (from LSASS, from the domain backup key, from the user's password) and decrypt everything the user left on the workstation; in the domain variant, stealing the **DPAPI backup key** from the DC allows decrypting any user's masterkey in the domain — including historical ones [^178^]. The practical value is enormous: browser password managers, VPN sessions, private keys, CI/CD tokens — everything lands in DPAPI [^178^].

### 7.5 NTLM relay and authentication coercion

**NTLM relay** remains the domain's basic knife: the attacker coerces the victim's authentication (coercion via **PetitPotam**/EFSRPC, **Printer Bug**/MS-RPRN, WebClient via a `.searchConnector-ms` file or a UNC path with an icon) and relays it to a service without signing — classically LDAP (→ RBCD/shadow credentials) or SMB (→ code execution) [^174^][^176^]. Fresh momentum for this class of attacks came from **CVE-2025-33073** — reflective NTLM relay on SMB (a machine's authentication relayed back to itself) with a public exploit, while LDAP protection-bypass variants are analyzed in parallel [^184^][^182^]. The defense is known but rarely complete: **required SMB signing**, **EPA/channel binding** on LDAPS and HTTPS (critical for ESC8!), disabling WebClient, segmentation, tiering, and limiting highly privileged accounts logging on to workstations [^176^][^174^]. Relaying to LDAP→RBCD and to AD CS web enrollment (ESC8) ties this section to lateral movement — today it is one of the fastest connectors "from zero to DA" [^183^][^198^].

---

## 8. Lateral movement (TA0008)

### 8.1 Authentication instead of exploits: PtH, PtT, OPtH

Lateral movement in AD is almost exclusively legitimate protocols with improper credentials: **Pass-the-Hash** (NTLM hash instead of a password), **Pass-the-Ticket** (injecting a stolen TGT/TGS into memory), **Overpass-the-Hash** (hash → AS request → a legitimate TGT, "logging in" with Kerberos from a hash), **Pass-the-Cert** (a certificate from AD CS as a TGT via PKINIT) [^188^][^192^]. Operators choose the protocol for the target service and monitoring: Kerberos leaves 4768/4769 on the DC, NTLM leaves 4624 type 3 on the host; PtH against protected accounts (Protected Users) will not work, because that group enforces Kerberos and disables NTLM [^192^][^120^].

### 8.2 Execution protocols: a decision tree

Choosing an execution method is a trade-off between loudness, artifacts, and required rights: **PsExec** (remote service via ADMIN$ — the loudest: 7045+4697, a binary on disk), **WMI** (`wmic process call create` — 4688 with parent WmiPrvSE, no service), **WinRM/PSRemoting** (5985/5986, interactive sessions, logged in PowerShell), **DCOM** (MMC20.Application, ShellWindows — no service creation, subtler), **RDP** (GUI, 4624 type 10), and **smbexec/wmiexec/atexec** from Impacket [^187^][^192^]. Validating privileges before execution: `nxc smb <subnet> -u user -p pass` with the **Pwn3d!** marker for local admin, `Find-LocalAdminAccess` from PowerView, and in the graph — the AdminTo/CanRDP/CanPSRemote edges in BloodHound [^118^][^119^].

### 8.3 Kerberos delegations and RBCD

Delegations are factory-made, often misunderstood impersonation rights: **unconstrained delegation** (a host holding users' TGTs in memory — Printer Bug on the DC from a delegated host = the DC's TGT), **constrained delegation** (S4U2Proxy to specified services — protocol transition allows forging tickets "on behalf of" any user without their password), **Resource-Based Constrained Delegation (RBCD)** (the `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute on the resource — an attacker with GenericWrite on a computer appends a controlled machine account and forges service tickets as administrator) [^193^][^197^]. RBCD is today the standard final step of relays to LDAP and of write-rights abuse in AD; detection: 5136 (delegation attribute change), 4662 on writes to computer objects, correlation with machine account creation (4741) by non-admins — MachineAccountQuota is 10 by default [^193^][^197^]. Also worth noting here is **BadSuccessor** (2025), disclosed by Akamai: abuse of delegated Managed Service Accounts (dMSA) in Windows Server 2025, where the attacker designates a template account (predecessor) and inherits its privileges; the detection is EID 5136 on the `msDS-ManagedAccountPrecededByLink` attribute [^120^].

### 8.4 AD CS: ESC1–ESC8 and certificate forgery

**Active Directory Certificate Services** is the second foundation of identity after Kerberos — and since the publication of "Certified Pre-Owned" (SpecterOps, 2021) it has become an escalation highway: **ESC1** (a template with enrollee-supplied subject + Client Authentication → a certificate as any user, including DA), **ESC2** (Any Purpose/SubCA template), **ESC3** (Certificate Request Agent), **ESC4** (writable template ACL → reconfigure into ESC1), **ESC5** (ACLs of PKI objects), **ESC6** (EDITF_ATTRIBUTESUBJECTALTNAME2 on the CA), **ESC7** (ManageCA/ManageCertificates), **ESC8** (NTLM relay to HTTP web enrollment) [^191^][^194^]. Tooling: **Certify** (C#, `Certify.exe find /vulnerable`) and **Certipy** (Python, `certipy find -vulnerable`, including relay and forge) [^194^]. Forged certificates provide **Pass-the-Cert** (a TGT via PKINIT), durable access even after a password change (a certificate is valid for years), and **shadow credentials** (appending a key to `msDS-KeyCredentialLink` — EID 5136 on this attribute is a signal) [^194^][^186^]. Detection: 4886/4887 (certificate request and issuance — correlating the SAN with the requester), 4899 (template modification), template auditing (`certipy find -vulnerable`, PSPKIAudit), and web enrollment monitoring [^120^][^198^].

| Technique | Requirement | Effect | Key detection |
|---|---|---|---|
| Pass-the-Hash | NTLM hash, local admin | SMB/WMI without password | 4624 type 3 NTLM from unusual stations [^188^] |
| Pass-the-Ticket | stolen TGT/TGS | Kerberos without password | ticket time/lifetime discrepancies [^192^] |
| Overpass-the-Hash | NTLM hash | legitimate TGT | 4768 with encryption anomalies [^192^] |
| PsExec / service | admin | SYSTEM execution | 7045/4697, ADMIN$ [^187^] |
| WMI / DCOM / WinRM | admin | execution without a service | 4688 (WmiPrvSE), 4104 [^192^] |
| RBCD | GenericWrite on the host | admin impersonation | 5136 (msDS-AllowedToAct…), 4741 [^193^] |
| Unconstrained del. + Printer Bug | delegated host | DC TGT | 4769 from delegated hosts [^197^] |
| AD CS ESC1/ESC8 | bad template / relay | DA certificate, PtC | 4886/4887, relay to HTTP enrollment [^194^] |

---

## 9. Command & Control (TA0011)

### 9.1 Frameworks: Cobalt Strike, Havoc, Sliver, Mythic

**Cobalt Strike** remains the commercial standard whose tradecraft defines the battlefield: **Malleable C2** profiles shape Beacon traffic to resemble legitimate services (headers, URIs, jitter), **sleep_mask** and BOFs limit memory exposure, **BeaconGate** (a system call proxy) and the **UDRL** (User-Defined Reflective Loader) replace the signature-detected loader — version 4.11 shifted the defaults toward quieter profiles, because the old defaults were detected instantly [^206^][^208^]. **Havoc** (free, younger) with the **Demon** agent offers indirect syscalls, sleep obfuscation (Ekko/FOLIAGE), and BOF attachment; the project was archived in February 2026, but forked variants live on in campaigns — including a variant with C2 via Microsoft Graph API/SharePoint detected by Fortinet [^214^][^219^]. The open-source landscape is completed by **Sliver** (Bishop Fox) and **Mythic** with the **Apollo** agent — with mTLS/HTTP(S)/DNS transports and modular post-exploitation. Choosing a framework means choosing a detection profile: Beacon is best known to the defense (so it requires the most customization), younger frameworks have fewer signatures, but their telemetry traces (e.g. characteristic TLS/JA3) quickly make it into rules [^215^][^205^].

### 9.2 Infrastructure and channels

C2 architecture is layered and conceptually similar to that described in the Linux compendium: implant → **redirector** (CDN, fronting through legitimate services, Apache mod_rewrite) → team server, with segregation of short-haul (SMB beacons inside the victim's network) and long-haul (HTTPS/DNS to the outside) [^130^]. The 2025–2026 trend is **channels through legitimate SaaS**: Microsoft Graph, SharePoint, Teams — traffic is encrypted, to trusted domains, with OAuth tokens, so detection shifts from the network to identity anomalies (impossible travel, unusual OAuth applications, consent phishing) [^219^]. DNS tunneling and DNS-over-HTTPS remain fallback channels with low bandwidth [^130^].

| Framework | License | Windows agent | Distinguisher | OPSEC note |
|---|---|---|---|---|
| Cobalt Strike | commercial | Beacon | BOF ecosystem, Malleable C2, UDRL [^206^] | best-known signatures — requires customization [^205^] |
| Havoc | open-source | Demon | indirect syscalls, Ekko/FOLIAGE out of the box [^215^] | project archived 02/2026; forks active [^214^] |
| Sliver | open-source | Go implant | fast cross-compile, mTLS, armory | characteristic certificates/JA3 |
| Mythic + Apollo | open-source | Apollo (C#) | web UI, scripting, integration | .NET in memory → AMSI/ETW to bypass |

---

## 10. Actions on objective (TA0040) and endgame scenarios

The "actions on objective" phase is defined by the ROE: data acquisition (staging, compression, exfiltration via HTTPS/DNS/OneDrive), ransomware simulation (without real destruction — flags, canaries), takeover of business processes (mailboxes, ERP, code repositories), maintaining long-term access until re-engagement [^124^][^209^]. In 2025–2026 the endgame scenario increasingly emulates high-turnover cybercrime: access brokers selling footholds to ransomware operators, groups like Scattered Spider combining helpdesk social engineering with the full AD chain (the M&S case), and extortion without encryption (pure exfiltration) [^209^][^120^]. The red team operator documents every step in a format reproducible for the blue team: time, ATT&CK technique, artifacts, telemetry the defense should have seen — because the product of the operation is improved detection, not trophies [^124^].

---

## 11. Blue Team counterpoint: how to detect it all

### 11.1 Baseline telemetry: Sysmon, Security Log, PowerShell, ETW

The foundation of Windows detection is a well-configured **Sysmon** (baseline configs: SwiftOnSecurity, sysmon-modular) with key events: **1** (processes with hashes and command lines), **3** (network), **6** (drivers — BYOVD), **7** (images/DLLs), **8** (CreateRemoteThread), **10** (ProcessAccess — LSASS), **11** (files), **12–14** (registry — persistence), **15** (file stream/ADS), **22** (DNS), **25** (process tampering — hollowing) [^199^][^207^]. On domain controllers, **Security** events rule: 4624/4625 (logons), 4662 (object access — DCSync), 4768/4769 (Kerberos — AS-REP/Kerberoasting), 4741/4742 (machine accounts), 5136 (attribute changes — RBCD, shadow credentials, dMSA), 4886/4887 (AD CS) [^120^][^199^]. **PowerShell 4104** (script block logging) sees malicious scripts even when AMSI bypasses are attempted, and **ETW** (including ETW-TI for injection detection) feeds EDRs — unless it has been patched (which is itself a signal) [^163^][^164^]. **Sigma** standardizes rules (DCSync via 4662 with GUIDs, Kerberoasting via 4769/RC4, LSASS access via Sysmon 10) and allows compiling them to any SIEM [^120^][^195^].

![Detection telemetry map](assets-rt-windows/wfig3-telemetria.png)

The map above shows how strongly each telemetry source "sees" the key offensive techniques: no single source suffices — DCSync is invisible to Sysmon on a workstation (the event is generated on the DC), a Silver Ticket does not touch the DC at all, and injections require ETW/EDR, because Sysmon 8/10 alone can be bypassed by syscalls [^199^][^175^][^163^]. Telemetry layering is therefore not an option but a necessary condition.

### 11.2 Identity-based detection and AD hardening

The identity layer consists of sensors on domain controllers of the ITDR/identity detection class (Kerberos anomalies, DCSync, golden ticket, directory reconnaissance) and behavioral detections in Entra ID (impossible travel, token theft). AD hardening boils down to removing the paths attackers walk: **administrative tiering** (Tier 0 accounts never on workstations), **LAPS** on local admins (kills PtH between hosts), **gMSA** and long service account passwords (kills Kerberoasting), **Protected Users** (enforces Kerberos, short tickets) [^119^][^120^]. Further: **SMB signing and LDAP channel binding** (kills relay), limiting **MachineAccountQuota**, ACL auditing (GenericAll/WriteDacl/WriteOwner), disabling unconstrained delegation, cleaning SPNs from sensitive accounts, and regular krbtgt resets (every 180 days) and DPAPI backup key rotation after every incident [^176^][^120^]. On endpoints: Credential Guard + LSA Protection (PPL), WDAC/AppLocker, Defender ASR rules (blocking LSASS dumps, PsExec/WMI child processes), tamper protection, and control of RMM installations [^190^][^209^]. BloodHound on the defense side (attack path management) allows prioritizing fixes with the greatest risk reduction [^122^].

---

## 12. Threat landscape 2025–2026

The **CrowdStrike Global Threat Report 2026** (data from 2025) sets the tone: **82% of detections malware-free**, average **breakout of 29 minutes** (65% faster year over year), fastest **27 seconds**, a 42% increase in zero-days exploited before publication, ClickFix +563%, spam +141%, an 89% increase in attacks by AI-enabled adversaries, and the enduring dominance of access brokers and BYOVD-based "EDR killers" [^200^][^209^]. The operator conclusion: the attacker wins not with better malware, but with better use of legitimate mechanisms — identity, RMM, trusted SaaS [^209^][^219^].

![Trends in the threat landscape](assets-rt-windows/wfig4-trendy.png)

Practical consequences for the red team: emulation must prefer identity-first tradecraft (relay, tickets, delegations, AD CS) over exploit-first; for the blue team — investment in identity detection and reaction speed (SOAR), because the half-hour breakout window makes manual alert analysis structurally too late [^200^][^201^].

---

## 13. Development path and laboratories

The best AD training environment is **GOAD** (Game of Active Directory, Orange Cyberdefense) — a multi-machine lab with deliberately misconfigured settings, covering almost all techniques described here (from Kerberoasting to ESC) [^218^][^216^]. Complements: HTB Pro Labs, TryHackMe (Hololive/Throwback), Vulnlab, and CRTO-style ranges. Reference knowledge channels: **LOLBAS** (living-off-the-land binaries), **LOLDrivers** (vulnerable drivers), **HijackLibs** (DLL hijacking), **WADComs** (an interactive Windows/AD command cheatsheet) — all aggregated by the "lolol" farm — plus HackTricks and the SpecterOps blogs [^204^][^122^].

| Certification | Level | Focus | Exam format |
|---|---|---|---|
| **CRTO** (Zero-Point Security) | intermediate-advanced | red team operations, Cobalt Strike, OPSEC, AD | 48 h, practical with flags [^220^][^221^] |
| CRTP (Altered Security) | intermediate | AD privesc/persistence (AD lab) | 24 h practical exam |
| OSCP (OffSec) | intermediate | general pentest + AD set | 24 h + report |
| OSEP (OffSec) | advanced | evasion, AV/EDR bypass, advanced AD | 48 h + report |
| GXPN / GDAT (SANS) | advanced | exploitation / AD detection | GIAC exams |

Recommended sequence for a Windows red team profile: AD fundamentals + GOAD → CRTO (the operator core) → OSEP (evasion) → specializations (AD CS, C++ tradecraft, EDR internals) [^220^].

---

## 14. Conclusion

Red team on Windows is a game about identity played on the most instrumented battlefield in computing: 78% of human-operated intrusions end at the domain controller, and 91% of environments already have paths from an ordinary user to dominant privileges [^120^]. Active Directory remains the central identity system whose compromise means the compromise of the entire organization [^127^]. The operator wins not with exploits, but with precise knowledge of the mechanisms — Kerberos, NTLM, delegations, AD CS, DPAPI — and an awareness of the telemetry each step generates [^155^][^191^]. The defender wins by removing paths (attack path management, tiering, LAPS, signing), layered telemetry (Sysmon + Security Log + ETW + identity), and a reaction speed proportional to the 29-minute breakout [^122^][^200^]. Both compendia — the Linux and the Windows one — close the full picture of modern red team tradecraft: from Linux kernel rootkits to Kerberos ticket forgery, from eBPF to ETW, from /proc to LSASS. Technique evolves every quarter; the principles — identity as the objective, footprint minimization, layered detection — remain constant.

---

*This material is strictly educational and informational in nature. It does not constitute legal advice or encouragement to act unlawfully. All described techniques should be used exclusively in authorized security tests and laboratory environments.*


---

[^118^]: https://medium.com/@DevkumarShah/mapping-a-full-active-directory-attack-path-a-hands-on-red-team-walkthrough-acbaa5a9c68a
[^119^]: https://hivesecurity.gitlab.io/blog/bloodhound-practical-guide-ad-attack-paths/
[^120^]: https://hivesecurity.gitlab.io/blog/ad-attack-chains-initial-access-to-domain-admin/
[^121^]: https://www.crowdstrike.com/en-us/cybersecurity-101/cyberattacks/mitre-attack-framework/
[^122^]: https://specterops.io/what-is-attack-path-management/
[^123^]: https://www.sans.org/cyber-security-courses/advanced-red-team-operations
[^124^]: https://redbotsecurity.com/red-teaming-mitre-attck-adversary-simulation/
[^125^]: https://www.picussecurity.com/resource/the-top-ten-mitre-attack-techniques
[^126^]: https://www.redfoxsec.com/blog/active-directory-attack-playbook-for-red-teamers
[^127^]: https://cybecloud.medium.com/ad-attack-chain-from-initial-access-to-domain-admin-ddf28672aebe
[^128^]: https://bishopfox.com/blog/active-directory-kill-chain
[^130^]: https://elhacker.info/Cursos/Stealth%20Cyber%20Operator%20[CSCO]/StealthOps_Red_Team_Tradecraft_Targeting_Enterprise_Security_Controls.pdf
[^131^]: https://bloodhound.specterops.io/collect-data/sharphound-data-permissions
[^132^]: https://ahsan.au/windows-privilege-escalation-tool-guide/
[^133^]: https://medium.com/@v445u/powerview-enumerating-and-mapping-active-directory-c1bdb8dfd400
[^134^]: https://hackers-arise.com/powershell-for-hackers-part-3-exploring-powerview/
[^135^]: https://github.com/MGamalCYSEC/Active-Directory-Enumeration-and-Attacks/blob/main/AD%20Enumeration/Manual%20Enumeration/PowerView.md
[^136^]: https://armur.ai/ethical-hacking/post/post-1/post-exploitation-privilege-escalation-tools/
[^137^]: https://www.exploit-db.com/docs/english/46990-active-directory-enumeration-with-powershell.pdf?ref=secjuice.com
[^138^]: https://powersploit.readthedocs.io/en/latest/Recon/
[^140^]: https://ipurple.team/2024/07/15/sharphound-detection/
[^141^]: https://securelayer7.net/learn/privilege-escalation/what-are-potato-attacks
[^142^]: https://integsec.com/blog/cve-2026-40369-windows-kernel-privilege-escalation-vulnerability-what-it-means-for-your-business-and-how-to-respond
[^143^]: https://www.sentinelone.com/vulnerability-database/cve-2026-24289/
[^144^]: https://sn0xs-organization.gitbook.io/sn0x-order.org/red-team-notes/windows-privilege-escalation/potato-attacks
[^146^]: https://fidelissecurity.com/vulnerabilities/cve-2025-62215/
[^150^]: https://socprime.com/blog/latest-threats/cve-2025-62215-windows-kernel-vulnerability/
[^152^]: https://bughra.dev/posts/windows-privilege-escalation/
[^153^]: https://netwrix.com/en/cybersecurity-glossary/cyber-security-attacks/golden-ticket-attack/
[^154^]: https://www.sentinelone.com/cybersecurity-101/cybersecurity/golden-ticket-attack/
[^155^]: https://medium.com/@iam_elango/kerberos-abuse-in-active-directory-golden-ticket-silver-ticket-diamond-ticket-attacks-explained-a6d73918dea8
[^156^]: https://www.hackingarticles.in/windows-privilege-escalation-bypass-uac/
[^157^]: https://www.cayosoft.com/blog/golden-ticket-attack/
[^158^]: https://www.ivanti.com/blog/dll-hijacking-prevention
[^159^]: https://www.crowdstrike.com/en-us/cybersecurity-101/cyberattacks/silver-ticket-attack/
[^160^]: https://www.redfoxsec.com/blog/persistence-techniques-for-red-team-operations
[^161^]: https://medium.com/@ccee.srmistrmp/memory-injection-in-malware-how-it-works-under-the-hood-e3648435980c
[^162^]: https://www.sentinelone.com/cybersecurity-101/cybersecurity/process-injection/
[^163^]: https://radiantsec.io/docs/redteam/bypass-amsi/
[^164^]: https://www.covertswarm.com/post/timeline-of-edr-bypass-techniques
[^165^]: https://hadess.io/wp-content/uploads/2023/10/EDR-Evasion-Techniques-using-Syscalls.pdf
[^166^]: https://windshock.github.io/en/post/2025-05-28-endpoint-security-evasion-techniques-20202025/
[^168^]: https://medium.com/@mathias.fuchs/ghosts-in-the-endpoint-how-attackers-evade-modern-edr-solutions-90ff4a07fdc2
[^170^]: https://github.com/topics/direct-syscalls
[^171^]: https://github.com/mukul975/Anthropic-Cybersecurity-Skills/blob/main/skills/detecting-t1055-process-injection-with-sysmon/SKILL.md
[^172^]: https://medium.com/@R3dLevy/evading-windows-security-bypass-amsi-65d639e2f35d
[^173^]: https://netwrix.com/en/cybersecurity-glossary/cyber-security-attacks/dcsync-attack/
[^174^]: https://www.thehacker.recipes/ad/movement/ntlm/relay
[^175^]: https://hivesecurity.gitlab.io/blog/dcsync-attack-detect-and-defend/
[^176^]: https://hivesecurity.gitlab.io/blog/ntlm-relay-attack-detect-2026/
[^178^]: https://github.com/Bhanunamikaze/DPAPI_BOF
[^180^]: https://www.deeptempo.ai/blogs/kerberoasting-the-attack-that-collects-without-connecting
[^182^]: https://www.crowdstrike.com/en-us/blog/analyzing-ntlm-ldap-authentication-bypass-vulnerability/
[^183^]: https://www.lrqa.com/en/cyber-labs/hash-relaying-the-path-to-domain-admin/
[^184^]: https://zeronetworks.com/blog/examining-relay-attacks-through-the-lens-of-cve-2025-33073
[^186^]: https://origin-unit42.paloaltonetworks.com/active-directory-certificate-services-exploitation/
[^187^]: https://github.com/yaklang/hack-skills/blob/main/skills/windows-lateral-movement/SKILL.md
[^188^]: https://www.hackingarticles.in/lateral-movement-pass-the-hash-attack/
[^190^]: https://deepstrike.io/blog/what-is-lsass-dumping
[^191^]: https://www.vaadata.com/en/blog/ad-cs-security-understanding-and-exploiting-esc-techniques/
[^192^]: https://pentests.dk/en/docs/pentest-methods/active-directory/lateral-movement/
[^193^]: https://netwrix.com/en/resources/blog/resource-based-constrained-delegation-abuse/
[^194^]: https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation
[^195^]: https://www.elastic.co/docs/reference/security/prebuilt-rules/rules/windows/credential_access_suspicious_lsass_access_memdump
[^196^]: https://medium.com/@maxwellcross/dumping-credentials-with-python-automating-lsass-access-and-credential-extraction-a8c79d36ff08
[^197^]: https://www.semperis.com/blog/ad-security-101-resource-based-constraint-delegation/
[^198^]: https://www.avertium.com/blog/escalation-8-how-to-close-a-commonly-exploited-active-directory-certificate-services-elevation-of-privilege-vulnerability
[^199^]: https://nxlog.co/news-and-blog/posts/sysmon-event-ids/
[^200^]: https://www.crowdstrike.com/en-us/blog/crowdstrike-2026-global-threat-report-findings/
[^201^]: https://www.crowdstrike.com/en-us/global-threat-report/
[^202^]: https://www.elastic.co/docs/reference/security/prebuilt-rules/audit_policies/windows/sysmon_eventid12_13_14_registry_event
[^204^]: https://lolol.farm/
[^205^]: https://whiteknightlabs.com/2025/05/19/harnessing-the-power-of-cobalt-strike-profiles-for-edr-evasion-part-2/
[^206^]: https://www.cobaltstrike.com/blog/cobalt-strike-411-shh-beacon-is-sleeping
[^207^]: https://www.decryptiondigest.com/blog/sysmon-configuration-soc-guide
[^208^]: https://www.cobaltstrike.com/blog/revisiting-the-udrl-part-2-obfuscation-masking
[^209^]: https://dokumen.pub/global-threat-report.html
[^213^]: https://www.huntress.com/blog/fake-tech-support-havoc-command-control
[^214^]: https://github.com/havocframework/havoc
[^215^]: https://www.redfoxsec.com/blog/havoc-c2-framework-a-red-teamers-complete-guide-to-setup-commands-and-tradecraft
[^216^]: https://www.it-connect.fr/goad-un-lab-entrainement-complet-pour-maitriser-la-securite-active-directory/
[^218^]: https://orange-cyberdefense.github.io/GOAD/
[^219^]: https://www.fortinet.com/blog/threat-research/havoc-sharepoint-with-microsoft-graph-api-turns-into-fud-c2
[^220^]: https://training.zeropointsecurity.co.uk/courses/red-team-ops
[^221^]: https://thehackerish.com/crto-certified-red-team-operator-honest-review/
