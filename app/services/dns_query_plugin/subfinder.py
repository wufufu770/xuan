import json
import os
import subprocess

from app.config import Config
from app.services.dns_query import DNSQueryBase


class Query(DNSQueryBase):
    def __init__(self):
        super(Query, self).__init__()
        self.source_name = "subfinder"

    def init_key(self, **kwargs):
        return

    def sub_domains(self, target):
        if not os.path.isfile(Config.SUBFINDER_BIN):
            raise RuntimeError("subfinder binary not found: {}".format(Config.SUBFINDER_BIN))

        cmd = [
            Config.SUBFINDER_BIN,
            "-d",
            target,
            "-silent",
            "-oJ",
            "-timeout",
            str(Config.SUBFINDER_TIMEOUT),
            "-max-time",
            str(max(1, int(Config.SUBFINDER_TIMEOUT / 60))),
        ]

        if Config.SUBFINDER_SOURCES:
            cmd.extend(["-s", ",".join(Config.SUBFINDER_SOURCES)])

        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=Config.SUBFINDER_TIMEOUT + 30,
            check=False,
        )

        if proc.returncode != 0:
            err = proc.stderr.strip() or proc.stdout.strip()
            raise RuntimeError("subfinder exit {}: {}".format(proc.returncode, err[:500]))

        results = []
        for line in proc.stdout.splitlines():
            line = line.strip()
            if not line:
                continue

            try:
                item = json.loads(line)
            except ValueError:
                results.append(line)
                continue

            host = item.get("host") or item.get("domain") or item.get("input")
            if host:
                results.append(host)

        return list(set(results))
