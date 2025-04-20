#!/usr/bin/env python3
import time
import statistics
import re
from pynput import keyboard
from datetime import datetime
import psutil
import platform
from collections import deque

class PrecisionKeyloggerDetector:
    def __init__(self):
        self.typing_speeds = deque(maxlen=500)
        self.last_key_time = time.time()
        self.baseline = None
        self.alert_count = 0
        self.consecutive_fast_keys = 0
        self.last_scan_time = 0
        self.suspicious_activities = []

        # Enhanced configuration
        self.config = {
            'min_samples': 30,
            'speed_threshold': 0.6,
            'required_consecutive': 5,
            'cooldown': 5.0,
            'min_alert_speed': 0.020,
            'scan_interval': 300,
            
            # Safe lists with improved patterns
            'safe_processes': {
                r'migration/\d+', r'idle_inject/\d+', 
                r'python\d*', r'systemd.*', r'rsyslogd', 
                r'dbus-daemon', r'sshd', r'bash', r'zsh',
                r'sh', r'dash', r'kworker.*', r'rcu.*'
            },
            'safe_ports': {80, 443, 53, 22, 3389, 631},
            
            # Suspicious patterns
            'suspicious_keywords': [
                'keylog', 'logger', 'rat', 'spy', 
                'steal', 'hook', 'klog', 'sniff',
                'inject', 'hijack', 'recorder'
            ]
        }

        print("\n🔍 Precision Keylogger Detector v2.1")
        print("⚡ Smart detection with minimal false positives\n")

    def is_safe_process(self, process_name):
        """Check if process is in safe list using regex patterns"""
        if not process_name:
            return False
            
        process_name = process_name.lower()
        for pattern in self.config['safe_processes']:
            if re.fullmatch(pattern, process_name):
                return True
        return False

    def scan_processes(self):
        """Scan processes with reduced false positives"""
        print("\n🔎 Scanning processes (smart mode)...")
        found_threats = False
        
        for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline']):
            try:
                proc_name = proc.info['name'] or ''
                proc_exe = proc.info['exe'] or ''
                proc_cmd = ' '.join(proc.info['cmdline'] or [])
                
                # Skip safe processes
                if self.is_safe_process(proc_name):
                    continue
                    
                # Check for suspicious indicators
                for keyword in self.config['suspicious_keywords']:
                    if (keyword in proc_name.lower() or 
                        keyword in proc_exe.lower() or 
                        keyword in proc_cmd.lower()):
                        self.log_threat(
                            f"Suspicious process: {proc_name} "
                            f"(PID: {proc.pid}, CMD: {proc_cmd[:50]}{'...' if len(proc_cmd) > 50 else ''})"
                        )
                        found_threats = True
                        break
                        
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
                
        if not found_threats:
            print("✅ No suspicious processes found")

    def scan_network(self):
        """Scan network connections with safe port list"""
        print("\n🌐 Scanning network connections...")
        found_threats = False
        
        for conn in psutil.net_connections(kind='inet'):
            if conn.status == 'ESTABLISHED' and conn.raddr:
                ip, port = conn.raddr
                if port not in self.config['safe_ports']:
                    try:
                        proc = psutil.Process(conn.pid)
                        proc_name = proc.name()
                        if not self.is_safe_process(proc_name):
                            self.log_threat(
                                f"Suspicious connection: {ip}:{port} "
                                f"(PID: {conn.pid}, Process: {proc_name})"
                            )
                            found_threats = True
                    except psutil.NoSuchProcess:
                        self.log_threat(
                            f"Orphaned connection: {ip}:{port} (PID: {conn.pid})"
                        )
                        found_threats = True
        
        if not found_threats:
            print("✅ No suspicious network activity found")

    def log_threat(self, message):
        """Log threats with timestamp"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"⚠️ [{timestamp}] {message}")
        self.suspicious_activities.append({
            'timestamp': timestamp,
            'threat': message
        })

    def on_press(self, key):
        """Handle key press events"""
        try:
            current_time = time.time()
            elapsed = current_time - self.last_key_time
            self.last_key_time = current_time

            if elapsed < 1.5 and hasattr(key, 'char'):
                self.typing_speeds.append(elapsed)
                
                # Update baseline if we have enough samples
                if len(self.typing_speeds) >= self.config['min_samples'] and not self.baseline:
                    self.baseline = {
                        'median': statistics.median(self.typing_speeds),
                        'mad': self.median_abs_deviation()
                    }
                    print(f"\n✅ Typing profile established (speed: {self.baseline['median']:.3f}s)")

                # Check for anomalies if baseline exists
                if self.baseline and (current_time - self.last_alert_time) > self.config['cooldown']:
                    self.check_anomaly(current_time, elapsed)

        except Exception:
            pass

    def median_abs_deviation(self):
        """Calculate Median Absolute Deviation"""
        if len(self.typing_speeds) < 2:
            return 0.1
        median = statistics.median(self.typing_speeds)
        return statistics.median(abs(x - median) for x in self.typing_speeds)

    def check_anomaly(self, current_time, elapsed):
        """Check for anomalous typing patterns"""
        speed_threshold = self.baseline['median'] * self.config['speed_threshold']
        
        if elapsed < self.config['min_alert_speed']:
            return
            
        if elapsed < speed_threshold:
            self.consecutive_fast_keys += 1
            if self.consecutive_fast_keys >= self.config['required_consecutive']:
                self.trigger_alert(current_time, elapsed)
        else:
            self.consecutive_fast_keys = max(0, self.consecutive_fast_keys - 1)

    def trigger_alert(self, current_time, current_speed):
        """Handle anomaly alerts"""
        self.last_alert_time = current_time
        self.alert_count += 1
        self.consecutive_fast_keys = 0

        timestamp = datetime.now().strftime("%H:%M:%S")
        deviation_pct = (self.baseline['median'] - current_speed) / self.baseline['median'] * 100
        
        print(f"\n🚨 [{timestamp}] Typing anomaly detected!")
        print(f"   ⚡ Speed: {current_speed:.3f}s ({deviation_pct:.1f}% faster than normal)")

    def start(self):
        """Start the monitoring system"""
        print("\n🛡️ Starting comprehensive monitoring...")
        self.scan_processes()
        self.scan_network()
        
        if platform.system() != 'Windows':
            print("\n⚠️ Some Windows-specific checks are not available")
        
        print("\n⌨️  Keyboard monitoring active - Type normally (ESC to quit)")
        with keyboard.Listener(
                on_press=self.on_press,
                on_release=lambda k: False if k == keyboard.Key.esc else None) as listener:
            listener.join()

        self.summary()

    def summary(self):
        """Print session summary"""
        print("\n📊 Detection Summary")
        print("-------------------")
        print(f"🔢 Keystrokes analyzed: {len(self.typing_speeds)}")
        if self.baseline:
            print(f"⏱️  Your typing speed: {self.baseline['median']:.3f}s ± {self.baseline['mad']:.3f}s")
        print(f"🚨 Anomalies detected: {self.alert_count}")
        
        if self.suspicious_activities:
            print("\n⚠️ Recent suspicious activities:")
            for activity in self.suspicious_activities[-3:]:
                print(f"   • [{activity['timestamp']}] {activity['threat']}")
        
        print("\n🔴 Monitoring ended")

if __name__ == "__main__":
    try:
        detector = PrecisionKeyloggerDetector()
        detector.start()
    except KeyboardInterrupt:
        print("\n🛑 Stopped by user")
    finally:
        if 'detector' in locals():
            detector.summary()
