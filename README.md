# MITM-DNS-SPOOFER

## DEPENDENCIES:
```
python3
python3-pip
```

---

## INSTALLATION:
```
git clone https://github.com/ilolm/dns-spoofer.git
cd dnf-spoofer
pip3 install -r requirements.txt
chmod +x dns_spoofer.py
```

---

## USAGE:
```
Usage: sudo ./dns_spoofer.py [options]

Options:
  -h, --help            show this help message and exit
  -d DOMAIN, --domain=DOMAIN
                        Enter here domain that you want to spoof. Put "*" to
                        spoof all domains.
  -i DST_IP, --destination-ip=DST_IP
                        Enter here an IP address that you want to bind with
                        entered domain.
```
