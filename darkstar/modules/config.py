from dotenv import load_dotenv
import os

load_dotenv()

#? Database config
db_config = {
    'user': os.getenv('DB_USER'),    
    'password': os.getenv('DB_PASSWORD'),     
    'host': os.getenv('DB_HOST'),
    'database': os.getenv('DB_NAME'),
}

#? Have i been pwned
HIBP_KEY = os.getenv('HIBP_KEY')

#? OpenVAS
OPENVAS_USER = os.getenv('OPENVAS_USER')
OPENVAS_PASSWORD = os.getenv('OPENVAS_PASSWORD')
