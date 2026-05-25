Installation
------------

The `dayshield-fix-rootfs-staging` helper is a small safety-net that extracts `boot/*` from the staged rootfs artifact into the updater staging path if those files are missing. This is a fallback that should be installed on appliances as an additional layer of protection.

Install steps (on appliance):

```bash
# copy the script to /usr/local/bin and make it executable
sudo cp packaging/systemd/dayshield-fix-rootfs-staging.sh /usr/local/bin/dayshield-fix-rootfs-staging.sh
sudo chmod 755 /usr/local/bin/dayshield-fix-rootfs-staging.sh

# install service and timer
sudo cp packaging/systemd/dayshield-fix-rootfs-staging.service /etc/systemd/system/
sudo cp packaging/systemd/dayshield-fix-rootfs-staging.timer /etc/systemd/system/

# enable and start the timer
sudo systemctl daemon-reload
sudo systemctl enable --now dayshield-fix-rootfs-staging.timer

# run once now to fix any current issues
sudo systemctl start dayshield-fix-rootfs-staging.service
```

Notes
-----
- The script is conservative: it only extracts `boot/*` from the staged artifact and will not modify other files. It uses a file lock to avoid concurrent runs.
- The timer runs every 2 minutes; adjust `OnUnitActiveSec` if you prefer a different cadence.
