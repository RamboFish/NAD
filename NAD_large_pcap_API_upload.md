***
# Importing pcap files larger than 1024 mb:

## 1. Detected and confirmed security incidents

From any screen, go to -> "Activity stream". This will open a list of all discovered security incident activities.
curl -u username:password -k -v -H "Content-Type: application/json" -X POST 'https://ip_addr:443/api/v2/sources/import' -d '{ "target": "not_exists", "create": true, "files": [ "file:///mnt/usb/file.pcap" ] }'
