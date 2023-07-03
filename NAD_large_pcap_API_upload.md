***
# Importing pcap files larger than 1024 mb:

## 1. Configure additional directories for PCAPs on the server

### Create new pcaps directory

`sudo mkdir /pcaps/uploads`

### Use vi or nano, to add the following line /opt/ptsecurity/etc/ptdpi.settings.yaml:

`pcap_path: /pcaps/uploads`

## 2. Restart NAD services

`sudo systemctl restart nad-*-server.service`

## 3. Method 1 (large PCAP is already uploaded on the server 

`curl -u username:password -k -v -H "Content-Type: application/json" -X POST 'https://ip_addr:443/api/v2/sources/import' -d '{ "target": "not_exists", "create": true, "files": [ "file:///mnt/usb/file.pcap" ] }'`
