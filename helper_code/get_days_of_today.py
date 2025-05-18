from datetime import datetime

today = datetime.now()
timestamp = int(today.timestamp())
a = timestamp // 86400

print(f"Today is {datetime.now().date()}")
print(f"Days since Unix epoch: {a}")