from datetime import datetime

def get_today_in_days():
    today = datetime.now()
    timestamp = int(today.timestamp())
    return timestamp // 86400
