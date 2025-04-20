#!/usr/bin/env python3
import time
import statistics
from pynput import keyboard
from datetime import datetime
import sys
import psutil
import socket

class BeastKeyloggerDetector:
    def __init__(self):
        self.typing_speeds = []
        self.last_key_time = time.time()
        self.running = True
        self.baseline = None
        self.alert_count = 0
        self.consecutive_fast_keys = 0
        self.last_alert_time = 0

        self.config = {
            'min_samples': 25,
            'max_samples': 300,
            'speed_threshold': 0.6,
            'required_consecutive': 4,
            'cooldown': 3.0,
            'min_alert_speed': 0.020
        }

        print("\n🛡️ BEAST Keylogger Detector")
        print("⚡ Typing monitor + Process/network scan started\n")

    def update_baseline(self):
        if len(self.typing_speeds) >= self.config['min_samples'] and not self.baseline:
            self.baseline = {
                'median': statistics.median(self.typing_speeds),
                'mad': self._median_abs_deviation()
            }
            print(f"\n✅ Typing Baseline set: {self.baseline['median']:.3f}s ± {self.baseline['mad']:.3f}s")
            print("🚀 Anomaly detection activated...\n")

    def _median_abs_deviation(self):
        if len(self.typing_speeds) < 2:
            return 0.1
        median = statistics.median(self.typing_speeds)
        return statistics.median(abs(x - median) for x in self.typing_speeds)

    def on_press(self, key):
        try:
            current_time = time.time()
            elapsed = current_time - self.last_key_time
            self.last_key_time = current_time

            if elapsed < 1.5 and hasattr(key, 'char'):
                self.typing_speeds.append(elapsed)
                if len(self.typing_speeds) > self.config['max_samples']:
                    self.typing_speeds.pop(0)

                self.update_baseline()

                if self.baseline:
                    self._check_anomaly(current_time, elapsed)
        except Exception:
            pass

    def _check_anomaly(self, current_time, elapsed):
        if (current_time - self.last_alert_time < self.config['cooldown'] or 
            elapsed < self.config['min_alert_speed']):
            return

        is_fast = elapsed < (self.baseline['median'] * self.config['speed_threshold'])

        if is_fast:
            self.consecutive_fast_keys += 1
            if self.consecutive_fast_keys >= self.config['required_consecutive']:
                self.alert(current_time, elapsed)
        else:
            self.consecutive_fast_keys = 0

    def alert(self, current_time, current_speed):
        self.last_alert_time = current_time
        self.alert_count += 1
        self.consecutive_fast_keys = 0

        timestamp = datetime.now().strftime("%H:%M:%S")
        deviation = (self.baseline['median'] - current_speed) / self.baseline['median']

        print(f"\n🚨 [{timestamp}] Anomaly #{self.alert_count}")
        print(f"   ⚡ Speed: {current_speed:.3f}s ({deviation:.0%} faster than baseline)")
        print(f"   🎯 Normal range: {self.baseline['median']:.3f}s ± {self.baseline['mad']:.3f}s")

    def scan_processes(self):
        print("\n🧠 Scanning processes for suspicious keyloggers...")
        suspicious_keywords = ['keylogger', 'logger', 'rat', 'spy', 'stealer', 'hook']
        for proc in psutil.process_iter(['pid', 'name', 'exe']):
            try:
                name = (proc.info['name'] or '').lower()
                exe = (proc.info['exe'] or '').lower()
                for keyword in suspicious_keywords:
                    if keyword in name or keyword in exe:
                        print(f"⚠️ Suspicious process: {name} (PID: {proc.pid})")
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

    def scan_network(self):
        print("\n🌐 Scanning for suspicious network activity...")
        for conn in psutil.net_connections(kind='inet'):
            if conn.status == 'ESTABLISHED' and conn.raddr:
                ip, port = conn.raddr
                if port not in [80, 443, 53]:
                    print(f"🚨 Suspicious connection: {ip}:{port} (PID: {conn.pid})")

    def start(self):
        self.scan_processes()
        self.scan_network()

        print("\n⌨️  Start typing (Press ESC to quit)...")
        with keyboard.Listener(
                on_press=self.on_press,
                on_release=lambda k: False if k == keyboard.Key.esc else None) as listener:
            listener.join()

        self.summary()

    def summary(self):
        print("\n📊 Session Summary:")
        if self.baseline:
            print(f"   🔢 Keystrokes analyzed: {len(self.typing_speeds)}")
            print(f"   ⏱️  Normal speed: {self.baseline['median']:.3f}s")
            print(f"   📈 Variability: ±{self.baseline['mad']:.3f}s")
        print(f"   🚨 Total alerts: {self.alert_count}")
        print("🔴 Detection complete.\n")


if __name__ == "__main__":
    try:
        detector = BeastKeyloggerDetector()
        detector.start()
    except KeyboardInterrupt:
        print("\n🛑 Interrupted by user.")
