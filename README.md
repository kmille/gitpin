# gitpin - ssl pinning for git

`gitpin` is a small tool allows you to manage ssl pinning for git. You can also uses it manually:

```bash
kmille@linbox:~ cat ~/.gitconfig
[includeIf "hasconfig:remote.*.url:https://github.com/**"]
path = /home/kmille/.gitconfig.d/github.com.inc

kmille@linbox:gitpin cat /home/kmille/.gitconfig.d/github.com.inc
[http]
pinnedPubkey = sha256//YH8+l6PDvIo1Q5o6varvw2edPgfyJFY5fHuSlsVdvdc=
```

# Walkthrough

[![asciicast](https://asciinema.org/a/568856.svg)](https://asciinema.org/a/568856)

## Features

```bash
kmille@linbox:gitpin ./gitpin --help         
usage: ./gitpin [-h|--help] [--system] [-s|--show-cert "<value>"] [-a|--add
                "<value>"] [-c|--check] [-u|--update] [-d|--delete "<value>"]
                [-v|--version]

                add ssl pinning to git

Arguments:

  -h  --help       Print help information
      --system     Use /etc/gitconfig instead of ~/.gitconfig
  -s  --show-cert  Show certificate of <domain>
  -a  --add        Add fingerprint for <domain>
  -c  --check      Check if fingerprints match
  -u  --update     Update fingerprints
  -d  --delete     Delete fingerprint for <domain>
  -v  --version    Show version
```

Please don't forget that these days SSL certificates expire after 90 days and you have to update the pin.
