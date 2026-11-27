# deploy/

| File | What it is |
|---|---|
| `smartdns-dashboard.service` | systemd unit, installed to `/etc/systemd/system/` |
| `install.sh` | installs from a git checkout. Run it from the repo root, not from inside `/opt/smartdns-dashboard`. |
| `nginx.conf.example` | reverse-proxy example, only if you have nginx to put in front |

For a server you reach over SFTP rather than git, build the single-file
installer instead — it is one text file that survives a text-mode transfer:

```bash
python3 tools/build_installer.py     # writes ./install.py
# copy install.py to the server, then:
python3 install.py --check-only
sudo python3 install.py
```
