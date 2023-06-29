Original article by rsvititch: https://github.com/rsvititch/PTNADWorkshop/wiki

***
# PT NAD Examples of useful filters in NAD:

## 1. Detected and confirmed security incidents

From any screen, go to -> "Activity stream". This will open a list of all discovered security incident activities.

## 2. Discovery of unsanctioned application usage

`(rpt.cat == "tor-relays" && app_proto == "tls" and rpt.where == "flow.dst") or alert.msg ~ "*[PTsecurity]*TOR*"` - Search of TOR related traffic

`app_proto == "bittorrent"` - Searches for torrent related traffic

`app_proto == "teamviewer"` - Searches for TeamViewer sessions

`alert.msg ~ "REMOTE*"` - Searches for other remote access utilities

`rpt.cat == "miners"` - Miners

`app_proto == openvpn` - OpenVPN usage

## 3. Clear text user data

`credentials.login && app_proto in (smtp, pop3, imap)` - Clear text user data in email traffic

`credentials.login && app_proto == "ldap"` - LDAP Clear text user data in LDAP traffic

## 4. Email with clear text passwords 
`(app_proto == "smtp" or app_proto == "pop3" or app_proto == "imap") and credentials.valid == 1 and credentials.password != "" and src.groups == "HOME_NET" and dst.groups == "HOME_NET"`

## 5. Unencrypted emails to external addresses (must confirm, that letters do not contain important information)
`(app_proto == "smtp" or app_proto == "pop3" or app_proto == "imap") && !(smtp.rqs.cmd.name == "STARTTLS" or pop3.rqs.cmd.name == "STLS" or imap.rqs.cmd.name == "STARTTLS") and dst.groups == "EXTERNAL_NET"`

## 6. HTTP basic auth
`credentials.valid == 1 and credentials.password != "" and app_proto == "http" and dst.groups == "HOME_NET"`

`credentials.login && app_proto == "http"`

## 7. FTP passwords
`credentials.valid == 1 and credentials.password != "" and app_proto == "ftp" and dst.groups == "HOME_NET"`

`credentials.login && app_proto == "ftp"`

## 8. Telnet protocol usage
`app_proto == "telnet"`

## 9. Proxy usage
`app_proto == "socks5"`

`(app_proto == socks5 || http.rqs.method == "CONNECT") && src.groups == "HOME_NET" && dst.groups == "HOME_NET"` - http or socks5 proxy usage within the internal network

## 10. Port scanning (Nmap syn scan)
`os.client ~ "*map*"`

## 11. Sinkholes
`app_proto != dns and rpt.cat == "sinkholes"` - connection attempts
 
`app_proto == dns and rpt.cat == "sinkholes"` - successful resolves

`dns(answer.ip == 127.0.0.1 && answer.rrname != "localhost")` - Suspicious resolves, possible "sleeper" C&C.

## 12. Servers with DDNS.
`rpt.cat == "ESC-DDNS-dns" and rpt.where == "flow.dst"`

`!rpt.cat == "ESC-DDNS-dns" and rpt.cat ~ "ESC*"`

## 13. llmnr and netbios
`app_proto == "nbns" or app_proto == "llmnr"`

## 14. Suspecious connections

`src.groups == EXTERNAL_NET && dst.port not in [25, 80, 443] && !errors && proto == "tcp" && bytes.recv > 800` - Non-standard TCP port connections from external networks

`dst.groups == "EXTERNAL_NET" && proto == "tcp" and dst.port not in (53, 80, 443)`  -  Non-standard TCP port connections to external networks

`ssh.tunnel` - SSH-tunnels

`rpt.cat == "dga" and rpt.where == "flow.dst"` - Connections to DGA domains

`dst.groups == "EXTERNAL_NET" && app_proto == "encrypted"` - Connections to external networks with custom encryption

`dcerpc.rqs.operation.params.service_name` - Sessions with remote service creation

*** 

Full documentation can be found here: [Official documentation (filters)](https://help.ptsecurity.com/projects/nad/11.0/en-US/help/1091135243)
