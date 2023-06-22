Документация по фильтрации запросов NAD:
[https://help.ptsecurity.com/projects/nad/11.0/ru-RU/help/1091135243](https://help.ptsecurity.com/projects/nad/11.0/ru-RU/help/1091135243)


***
# Примеры полезных фильтров для работы со сведениями, собранными в PT NAD

## 1. Выявленные инциденты ИБ

Перейдите на "Стартовый экран -> Лента активностей". Откроется список обнаруженных активностей, связанных с инцидентами ИБ.

## 2. Выявление несанкционированного использования приложений

`(rpt.cat == "tor-relays" && app_proto == "tls" and rpt.where == "flow.dst") or alert.msg ~ "*[PTsecurity]*TOR*"` - поиск трафика, относящегося к сетям TOR

`app_proto == "bittorrent"` - поиск torrent клиентов

`app_proto == "teamviewer"` - поиск сессий TeamViewer

`alert.msg ~ "REMOTE*"` - прочие утилиты удаленного доступа

`rpt.cat == "miners"` - майнеры

`app_proto == openvpn` - использование openVPN

## 3. Передача учетных данных в открытом виде

`credentials.login && app_proto in (smtp, pop3, imap)` - передача учетных данных в открытом виде в почтовом трафике

`credentials.login && app_proto == "ldap"` - передача учетных данных в открытом виде по протоколу LDAP

## 4. Почта с паролями в открытом виде
`(app_proto == "smtp" or app_proto == "pop3" or app_proto == "imap") and credentials.valid == 1 and credentials.password != "" and src.groups == "HOME_NET" and dst.groups == "HOME_NET"`

## 5. Почта во внешнюю сеть без шифрования (нужно убедиться, что в письмах есть что-то важное)
`(app_proto == "smtp" or app_proto == "pop3" or app_proto == "imap") && !(smtp.rqs.cmd.name == "STARTTLS" or pop3.rqs.cmd.name == "STLS" or imap.rqs.cmd.name == "STARTTLS") and dst.groups == "EXTERNAL_NET"`

## 6. HTTP basic auth
`credentials.valid == 1 and credentials.password != "" and app_proto == "http" and dst.groups == "HOME_NET"`

`credentials.login && app_proto == "http"`

## 7. FTP пароли
`credentials.valid == 1 and credentials.password != "" and app_proto == "ftp" and dst.groups == "HOME_NET"`

`credentials.login && app_proto == "ftp"`

## 8. Использование протокола Telnet
`app_proto == "telnet"`

## 9. Использование прокси
`app_proto == "socks5"`

`(app_proto == socks5 || http.rqs.method == "CONNECT") && src.groups == "HOME_NET" && dst.groups == "HOME_NET"` - Использование http или socks5 прокси серверов внутри инфраструктуры

## 10. Сканирование портов (Nmap syn scan)
`os.client ~ "*map*"`

## 11. Синкхолы
`app_proto != dns and rpt.cat == "sinkholes"` - попытки подключения
 
`app_proto == dns and rpt.cat == "sinkholes"` - успешные резолвы

`dns(answer.ip == 127.0.0.1 && answer.rrname != "localhost")` - подозрительные резолвы. Возможно "спящие" C&C.

## 12. Серверы с DDNS.
`rpt.cat == "ESC-DDNS-dns" and rpt.where == "flow.dst"`

`!rpt.cat == "ESC-DDNS-dns" and rpt.cat ~ "ESC*"`

## 13. llmnr и netbios
`app_proto == "nbns" or app_proto == "llmnr"`

## Подозрительные соединения

`src.groups == EXTERNAL_NET && dst.port not in [25, 80, 443] && !errors && proto == "tcp" && bytes.recv > 800` - TCP соединения из внешней сети на нестандартные порты

`dst.groups == "EXTERNAL_NET" && proto == "tcp" and dst.port not in (53, 80, 443)`  -  TCP соединения во внешнюю сеть на нестандартные порты

`ssh.tunnel` - SSH-туннели

`rpt.cat == "dga" and rpt.where == "flow.dst"` - подключение к DGA доменам

`dst.groups == "EXTERNAL_NET" && app_proto == "encrypted"` - шифрованные подключения во внешнюю сеть (кастомное шифрование)

`dcerpc.rqs.operation.params.service_name` - сессии с удаленным созданием сервисов