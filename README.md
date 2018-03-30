# ipset_lists

## Install

```bash
curl https://raw.githubusercontent.com/tomlobato/ipset_lists/master/ipset_lists.rb > ipset_lists
chmod 755 ipset_lists
mv ipset_lists /usr/local/sbin/ipset_lists
```

## Usage

```bash
# ipset_lists country_br
Created ipset country_br (ipv4: 3028, ipv6: 5137)

# ipset_lists country_ru
Created ipset country_ru (ipv4: 7146, ipv6: 1555)

# ipset_lists aws
Created ipset aws (ipv4: 1110, ipv6: 408)
```

## iptables examples:

```bash
iptables -I INPUT -p tcp -m multiport --dport 80,443,53 -m set --match-set country_br src -j DROP
iptables -I INPUT -m set --match-set country_br src -j REJECT
```

## Lists supported

- Countries (```ipset_lists country_br```)
- AWS (```ipset_lists country_br```)

On the way...

- CDNs (Cloudfare, MaxCDN, CloudFront...)
- Tor exit nodes
- all_good (sum of the good guys: pingdom, cdn\`s...)
- all_bad (sum of the evil incarnation on the earth)
- bots
- MaxMind GeoIP Anonymous Proxies
- Firehol blocklist

## TODO

- Add more sources
- Add whitelist sources
- Turn into a gem
- Instrumentation: analize iptables performance (w and w/o ipset\`s)
