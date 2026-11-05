#!/usr/bin/env python3
import asyncio
import collections
import ipaddress
import json
import os
import re
import socket
import time

CONFIG_PATH = os.environ.get("RESPONDER_CONFIG", "/etc/responder/playbook.json")
CONTROL_PATH = os.environ.get("RESPONDER_CONTROL", "/run/responder/ctl.sock")
IGNORED_IDENTS = {"responder", "fw-response", "sshd", "sshd-session", "dmztest"}
MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")
REASON_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,48}$")
UNITS = {"ms": 0.001, "s": 1, "m": 60, "h": 3600, "d": 86400}

Signal = collections.namedtuple("Signal", "kind subject key summary")


def now():
    return time.time()


def log(text):
    print(f"{time.strftime('%H:%M:%S')} {text}", flush=True)


def as_ip(value):
    try:
        return str(ipaddress.IPv4Address(str(value).strip()))
    except (ipaddress.AddressValueError, ValueError):
        return None


def parse_duration(text):
    return sum(int(v) * UNITS[u] for v, u in re.findall(r"(\d+)(ms|d|h|m|s)", text or ""))


def split_addr(text):
    host, port = text.rsplit(":", 1)
    return host, int(port)


class Nets:
    def __init__(self, cidrs):
        self.nets = [ipaddress.IPv4Network(c) for c in cidrs]

    def __contains__(self, ip):
        try:
            addr = ipaddress.IPv4Address(ip)
        except (ipaddress.AddressValueError, ValueError):
            return False
        return any(addr in n for n in self.nets)


class Playbook:
    def __init__(self, data):
        self.id = data["id"]
        self.name = data["name"]
        self.trigger = data["trigger"]
        self.threshold = int(data["threshold"])
        self.window = float(data["window"])
        self.distinct = bool(data.get("distinct", False))
        self.action = data["action"]


class Config:
    def __init__(self, data):
        self.mode = os.environ.get("RESPONDER_MODE") or data.get("mode", "enforce")
        if self.mode not in ("enforce", "monitor"):
            self.mode = "enforce"
        self.listen = split_addr(data["listen"])
        self.syslog = split_addr(data["syslog"])
        fw = data["firewall"]
        self.fw_host = fw["host"]
        self.fw_user = fw["user"]
        self.fw_key = fw["key"]
        self.fw_known_hosts = fw["known_hosts"]
        self.waf = data["waf"]
        self.web = data["web"]
        self.protected = Nets(data["protected"])
        self.internal = Nets(data["internal"])
        self.dmz = Nets(data["dmz"])
        self.private = Nets(data["private"])
        self.block_seconds = int(data["block_seconds"])
        self.max_block_seconds = int(data["max_block_seconds"])
        self.escalation = float(data["escalation"])
        self.offense_memory = float(data["offense_memory_seconds"])
        self.quarantine_seconds = int(data["quarantine_seconds"])
        self.max_actions_per_minute = int(data["max_actions_per_minute"])
        self.playbooks = [Playbook(p) for p in data["playbooks"]]

    @classmethod
    def load(cls, path):
        with open(path, encoding="utf-8") as fh:
            return cls(json.load(fh))


def classify(rec, cfg):
    ident = rec.get("ident", "")
    if ident in IGNORED_IDENTS:
        return []
    if ident == "modsecurity" and rec.get("status"):
        ip = as_ip(rec.get("client"))
        if not ip:
            return []
        uri = rec.get("uri", "-")
        return [Signal("waf_block", ip, uri, f"WAF {rec.get('status')} {uri} score {rec.get('score', '?')}")]
    if ident == "suricata" and rec.get("event_type") == "alert":
        alert = rec.get("alert") if isinstance(rec.get("alert"), dict) else {}
        sid = str(alert.get("signature_id", "?"))
        sig = alert.get("signature", "?")
        src = as_ip(rec.get("src_ip"))
        dst = as_ip(rec.get("dest_ip"))
        port = rec.get("dest_port", "?")
        if src == cfg.waf and dst == cfg.web:
            ip = as_ip(rec.get("client"))
            if ip and ip != cfg.waf:
                return [Signal("ids_behind_waf", ip, sid, f"IDS behind WAF: {sig}")]
            return []
        if src and dst and src in cfg.dmz and dst not in cfg.private:
            return [Signal("ids_egress", dst, f"{src}:{port}", f"IDS {src} -> {dst}:{port}: {sig}")]
        return []
    if ident == "ulogd" and rec.get("fw_rule"):
        rule = rec["fw_rule"]
        if not (rule.endswith(" input drop") or rule.endswith(" forward drop")):
            return []
        src = as_ip(rec.get("client"))
        dst = as_ip(rec.get("dst"))
        if not src:
            return []
        port = rec.get("dpt") or rec.get("proto", "?")
        if src in cfg.internal and dst and dst in cfg.private:
            return [Signal("fw_drop_internal", src, f"{dst}:{port}", f"{rule} {src} -> {dst}:{port}")]
        if src not in cfg.private:
            return [Signal("fw_drop_external", src, str(port), f"{rule} {src} -> {dst}:{port}")]
    return []


def parse_element(line):
    m = re.match(r"^(blocklist|quarantine) (\S+)(.*)$", line)
    if not m or not as_ip(m.group(2)):
        return None
    rest = m.group(3)
    expires = re.search(r"expires (\S+)", rest)
    comment = re.search(r'comment "([^"]*)"', rest)
    return {
        "set": m.group(1),
        "ip": m.group(2),
        "expires": now() + parse_duration(expires.group(1)) if expires else None,
        "reason": comment.group(1) if comment else "-",
    }


class Audit:
    def __init__(self, addr):
        self.addr = addr
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.history = collections.deque(maxlen=500)

    def emit(self, action, **fields):
        rec = {"action": action}
        rec.update({k: v for k, v in fields.items() if v is not None})
        if action != "state":
            self.history.append(dict(rec, ts=round(now(), 3)))
            log(json.dumps(rec, ensure_ascii=False))
        t = time.localtime()
        stamp = f"{MONTHS[t.tm_mon - 1]} {t.tm_mday:2d} {t.tm_hour:02d}:{t.tm_min:02d}:{t.tm_sec:02d}"
        line = f"<134>{stamp} siem responder: {json.dumps(rec, ensure_ascii=False, separators=(',', ':'))}"
        try:
            self.sock.sendto(line.encode("utf-8"), self.addr)
        except OSError as exc:
            log(f"audit send failed: {exc}")


class Firewall:
    def __init__(self, cfg, on_change):
        self.cfg = cfg
        self.on_change = on_change
        self.proc = None
        self.lock = asyncio.Lock()
        self.connected = False
        self.last_error = ""

    def command(self):
        c = self.cfg
        return [
            "ssh", "-T", "-F", "/dev/null",
            "-i", c.fw_key,
            "-o", "IdentitiesOnly=yes",
            "-o", "BatchMode=yes",
            "-o", f"UserKnownHostsFile={c.fw_known_hosts}",
            "-o", "StrictHostKeyChecking=yes",
            "-o", "HostKeyAlgorithms=ecdsa-sha2-nistp384",
            "-o", "KexAlgorithms=ecdh-sha2-nistp384",
            "-o", "Ciphers=aes256-gcm@openssh.com",
            "-o", "PubkeyAcceptedAlgorithms=ecdsa-sha2-nistp384",
            "-o", "ConnectTimeout=3",
            "-o", "ServerAliveInterval=5",
            "-o", "ServerAliveCountMax=2",
            "-o", "LogLevel=ERROR",
            f"{c.fw_user}@{c.fw_host}", "session",
        ]

    async def _drain_stderr(self, proc):
        while True:
            raw = await proc.stderr.readline()
            if not raw:
                return
            self.last_error = raw.decode(errors="replace").strip()
            log(f"ssh: {self.last_error}")

    async def _connect(self):
        self.proc = await asyncio.create_subprocess_exec(
            *self.command(),
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        asyncio.get_running_loop().create_task(self._drain_stderr(self.proc))
        raw = await asyncio.wait_for(self.proc.stdout.readline(), 10)
        if not raw.startswith(b"OK session"):
            raise ConnectionError(self.last_error or "no session banner")
        self.connected = True
        self.on_change(True, "")

    async def _drop(self, reason):
        was = self.connected
        self.connected = False
        if self.proc and self.proc.returncode is None:
            self.proc.kill()
            try:
                await asyncio.wait_for(self.proc.wait(), 2)
            except asyncio.TimeoutError:
                pass
        self.proc = None
        if was:
            self.on_change(False, str(reason))

    async def call(self, line, timeout=5):
        async with self.lock:
            error = ""
            for _ in range(2):
                try:
                    if not self.connected:
                        await self._connect()
                    self.proc.stdin.write((line + "\n").encode())
                    await self.proc.stdin.drain()
                    lines = []
                    while True:
                        raw = await asyncio.wait_for(self.proc.stdout.readline(), timeout)
                        if not raw:
                            raise ConnectionError(self.last_error or "channel closed")
                        text = raw.decode(errors="replace").rstrip("\n")
                        if text.startswith("OK") or text.startswith("ERR"):
                            return text.startswith("OK"), text, lines
                        lines.append(text)
                except (OSError, ConnectionError, asyncio.TimeoutError) as exc:
                    error = str(exc) or exc.__class__.__name__
                    await self._drop(error)
            return False, f"ERR channel {error}", []


class Responder:
    def __init__(self, cfg):
        self.cfg = cfg
        self.mode = cfg.mode
        self.audit = Audit(cfg.syslog)
        self.fw = Firewall(cfg, self.channel_changed)
        self.windows = {}
        self.active = {}
        self.virtual = {}
        self.offenses = {}
        self.pending = set()
        self.recent = collections.deque()
        self.queue = asyncio.Queue()
        self.counters = collections.Counter()
        self.suppressed_at = 0.0

    def channel_changed(self, up, reason):
        self.audit.emit("channel", result="up" if up else "down", reason=reason or None)
        self.emit_state()

    def emit_state(self):
        blocks = sum(1 for e in self.active.values() if e["set"] == "blocklist")
        self.audit.emit(
            "state",
            mode=self.mode,
            enforce=1 if self.mode == "enforce" else 0,
            blocks=blocks,
            quarantined=len(self.active) - blocks,
            channel=1 if self.fw.connected else 0,
        )

    def contained(self, ip):
        return ip in self.active or ip in self.pending or self.virtual.get(ip, 0) > now()

    def ingest(self, rec):
        self.counters["events"] += 1
        date = rec.get("date")
        t_event = float(date) if isinstance(date, (int, float)) else None
        if t_event is not None and not 0 <= now() - t_event < 60:
            t_event = None
        for sig in classify(rec, self.cfg):
            self.counters["signals"] += 1
            self.evaluate(sig, t_event or now())

    def evaluate(self, sig, t_event):
        t = now()
        for pb in self.cfg.playbooks:
            if pb.trigger != sig.kind or self.contained(sig.subject):
                continue
            w = self.windows.setdefault((pb.id, sig.subject), collections.deque())
            w.append((t, sig.key, sig.summary))
            while w and t - w[0][0] > pb.window:
                w.popleft()
            count = len({k for _, k, _ in w}) if pb.distinct else len(w)
            if count < pb.threshold:
                continue
            evidence = [s for _, _, s in list(w)[-5:]]
            w.clear()
            self.trigger(pb, sig.subject, count, evidence, t_event)

    def trigger(self, pb, ip, count, evidence, t_event):
        if ip in self.cfg.protected:
            self.audit.emit("refused", client=ip, playbook=pb.id, name=pb.name, result="protected", trigger=" | ".join(evidence))
            return
        kind = pb.action
        if kind == "block" and ip in self.cfg.internal:
            kind = "quarantine"
        self.pending.add(ip)
        self.queue.put_nowait({
            "kind": kind, "ip": ip, "playbook": pb.id, "name": pb.name, "count": count,
            "evidence": evidence, "t_event": t_event, "source": "auto", "reason": pb.id,
        })

    def block_seconds(self, ip):
        count, last = self.offenses.get(ip, (0, 0.0))
        if now() - last > self.cfg.offense_memory:
            count = 0
        return int(min(self.cfg.block_seconds * self.cfg.escalation ** count, self.cfg.max_block_seconds))

    def note_offense(self, ip):
        count, last = self.offenses.get(ip, (0, 0.0))
        if now() - last > self.cfg.offense_memory:
            count = 0
        self.offenses[ip] = (count + 1, now())

    def allow_action(self):
        t = now()
        while self.recent and t - self.recent[0] > 60:
            self.recent.popleft()
        if len(self.recent) >= self.cfg.max_actions_per_minute:
            if t - self.suppressed_at > 10:
                self.suppressed_at = t
                self.audit.emit("suppressed", result=f"more than {self.cfg.max_actions_per_minute} actions per minute")
            return False
        self.recent.append(t)
        return True

    async def worker(self):
        while True:
            act = await self.queue.get()
            try:
                await self.execute(act)
            except Exception as exc:
                log(f"action failed: {exc!r}")
            finally:
                self.pending.discard(act["ip"])

    async def execute(self, act):
        ip = act["ip"]
        kind = act["kind"]
        auto = act["source"] == "auto"
        if "seconds" in act:
            seconds = act["seconds"]
        elif kind == "block":
            seconds = self.block_seconds(ip)
        else:
            seconds = self.cfg.quarantine_seconds
        common = {
            "client": ip, "playbook": act.get("playbook"), "name": act.get("name"),
            "seconds": seconds, "count": act.get("count"), "source": act["source"],
            "trigger": " | ".join(act.get("evidence", [])) or None,
        }
        if auto:
            if not self.allow_action():
                return False, "ERR suppressed"
            if self.mode != "enforce":
                self.virtual[ip] = now() + (seconds or self.cfg.block_seconds)
                self.audit.emit(f"would_{kind}", mode=self.mode, **common)
                return True, f"OK would_{kind} {ip}"
        t_call = now()
        ok, reply, _ = await self.fw.call(f"{kind} {ip} {seconds} {act['reason']}")
        t_done = now()
        if not ok:
            self.counters["errors"] += 1
            self.audit.emit("refused" if "protected" in reply or "not internal" in reply else "error", result=reply, **common)
            return False, reply
        self.counters["actions"] += 1
        self.active[ip] = {
            "set": "blocklist" if kind == "block" else "quarantine",
            "expires": t_done + seconds if seconds else None,
            "reason": act["reason"],
            "since": t_done,
        }
        self.virtual.pop(ip, None)
        if auto and kind == "block":
            self.note_offense(ip)
        flows = re.search(r"flows=(\d+)", reply)
        self.audit.emit(
            kind,
            mode=self.mode,
            latency_ms=int((t_done - act["t_event"]) * 1000) if auto else None,
            fw_ms=int((t_done - t_call) * 1000),
            flows=int(flows.group(1)) if flows else None,
            **common,
        )
        self.emit_state()
        return True, reply

    async def sync(self, announce=False):
        ok, reply, lines = await self.fw.call("list")
        if not ok:
            return False, reply, []
        fresh = {}
        for line in lines:
            e = parse_element(line)
            if e:
                old = self.active.get(e["ip"], {})
                fresh[e["ip"]] = {"set": e["set"], "expires": e["expires"], "reason": e["reason"], "since": old.get("since", now())}
        changed = set(fresh) != set(self.active)
        self.active = fresh
        if announce or changed:
            self.audit.emit("sync", blocks=len(fresh))
            self.emit_state()
        return True, reply, lines

    async def housekeeping(self):
        tick = 0
        while True:
            await asyncio.sleep(1)
            tick += 1
            t = now()
            for ip, e in list(self.active.items()):
                if e["expires"] and e["expires"] <= t:
                    del self.active[ip]
                    self.audit.emit("expire", client=ip, playbook=e["reason"], result=e["set"])
                    self.emit_state()
            for ip, until in list(self.virtual.items()):
                if until <= t:
                    del self.virtual[ip]
            for key, w in list(self.windows.items()):
                if not w or t - w[-1][0] > 600:
                    del self.windows[key]
            if tick % 5 == 0:
                self.emit_state()
            if tick % 30 == 0 and self.fw.connected:
                await self.sync()

    async def maintain(self):
        delay = 1
        while True:
            if not self.fw.connected:
                ok, reply, _ = await self.fw.call("ping")
                if ok:
                    delay = 1
                    await self.sync(announce=True)
                else:
                    log(f"firewall channel not ready: {reply}")
                    delay = min(delay * 2, 10)
                await asyncio.sleep(delay)
                continue
            await asyncio.sleep(10)
            if not self.fw.lock.locked():
                await self.fw.call("ping")

    async def events(self, reader, writer):
        try:
            while True:
                raw = await reader.readline()
                if not raw:
                    break
                try:
                    rec = json.loads(raw)
                except ValueError:
                    self.counters["invalid"] += 1
                    continue
                if isinstance(rec, dict):
                    self.ingest(rec)
        finally:
            writer.close()

    def operator_action(self, kind, req):
        ip = as_ip(req.get("ip"))
        if not ip:
            return None, {"ok": False, "error": "invalid address"}
        if ip in self.cfg.protected:
            self.audit.emit("refused", client=ip, source="operator", result="protected")
            return None, {"ok": False, "error": f"protected {ip}"}
        default = self.cfg.block_seconds if kind == "block" else self.cfg.quarantine_seconds
        try:
            seconds = int(req.get("seconds", default))
        except (TypeError, ValueError):
            return None, {"ok": False, "error": "invalid seconds"}
        reason = str(req.get("reason") or "operator")
        if not REASON_RE.match(reason):
            return None, {"ok": False, "error": "invalid reason"}
        return {
            "kind": kind, "ip": ip, "seconds": seconds, "reason": reason, "source": "operator",
            "playbook": "operator", "name": "Operator",
        }, None

    def status(self):
        t = now()
        return {
            "ok": True,
            "mode": self.mode,
            "channel": self.fw.connected,
            "firewall": self.cfg.fw_host,
            "active": [
                {"ip": ip, "set": e["set"], "reason": e["reason"],
                 "expires_in": int(e["expires"] - t) if e["expires"] else None}
                for ip, e in sorted(self.active.items())
            ],
            "offenses": {ip: c for ip, (c, _) in self.offenses.items()},
            "counters": dict(self.counters),
            "playbooks": [f"{p.id} {p.name}" for p in self.cfg.playbooks],
        }

    async def command(self, req):
        cmd = req.get("cmd")
        if cmd == "status":
            return self.status()
        if cmd == "mode":
            value = req.get("value")
            if value is None:
                return {"ok": True, "mode": self.mode}
            if value not in ("enforce", "monitor"):
                return {"ok": False, "error": "mode must be enforce or monitor"}
            if value != self.mode:
                self.mode = value
                self.virtual.clear()
                self.audit.emit("mode", mode=value, source="operator")
                self.emit_state()
            return {"ok": True, "mode": self.mode}
        if cmd in ("block", "quarantine"):
            act, err = self.operator_action(cmd, req)
            if err:
                return err
            ok, reply = await self.execute(act)
            return {"ok": ok, "message": reply}
        if cmd == "release":
            ip = as_ip(req.get("ip"))
            if not ip:
                return {"ok": False, "error": "invalid address"}
            ok, reply, _ = await self.fw.call(f"release {ip}")
            if ok:
                entry = self.active.pop(ip, None)
                self.virtual.pop(ip, None)
                self.audit.emit("release", client=ip, source="operator", result=entry["set"] if entry else None)
                self.emit_state()
            return {"ok": ok, "message": reply}
        if cmd == "flush":
            ok, reply, _ = await self.fw.call("flush")
            if ok:
                self.active.clear()
                self.virtual.clear()
                self.audit.emit("flush", source="operator")
                self.emit_state()
            return {"ok": ok, "message": reply}
        if cmd == "reset":
            self.windows.clear()
            self.offenses.clear()
            self.virtual.clear()
            self.recent.clear()
            self.audit.emit("reset", source="operator")
            return {"ok": True, "message": "OK reset"}
        if cmd == "list":
            ok, reply, lines = await self.fw.call("list")
            return {"ok": ok, "lines": lines, "message": reply}
        if cmd == "sync":
            ok, reply, lines = await self.sync(announce=True)
            return {"ok": ok, "lines": lines, "message": reply}
        if cmd == "stats":
            ok, reply, _ = await self.fw.call("stats")
            return {"ok": ok, "message": reply}
        if cmd == "history":
            try:
                n = max(1, min(int(req.get("n", 20)), 500))
            except (TypeError, ValueError):
                n = 20
            return {"ok": True, "history": list(self.audit.history)[-n:]}
        return {"ok": False, "error": f"unknown command {cmd!r}"}

    async def control(self, reader, writer):
        try:
            raw = await asyncio.wait_for(reader.readline(), 5)
            res = await self.command(json.loads(raw))
        except Exception as exc:
            res = {"ok": False, "error": str(exc)}
        writer.write((json.dumps(res, ensure_ascii=False) + "\n").encode("utf-8"))
        try:
            await writer.drain()
        finally:
            writer.close()


async def main():
    cfg = Config.load(CONFIG_PATH)
    responder = Responder(cfg)
    os.makedirs(os.path.dirname(CONTROL_PATH), exist_ok=True)
    if os.path.exists(CONTROL_PATH):
        os.unlink(CONTROL_PATH)
    await asyncio.start_unix_server(responder.control, path=CONTROL_PATH)
    os.chmod(CONTROL_PATH, 0o660)
    host, port = cfg.listen
    await asyncio.start_server(responder.events, host, port)
    responder.audit.emit("start", mode=responder.mode, result=", ".join(p.id for p in cfg.playbooks))
    log(f"listening for events on {host}:{port}, firewall {cfg.fw_user}@{cfg.fw_host}, mode {responder.mode}")
    await asyncio.gather(responder.worker(), responder.housekeeping(), responder.maintain())


if __name__ == "__main__":
    asyncio.run(main())
