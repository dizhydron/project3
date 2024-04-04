from http.server import BaseHTTPRequestHandler, HTTPServer 
from Crypto.PublicKey import RSA
from urllib.parse import urlparse, parse_qs
import base64
import json
import jwt
import datetime
import threading
import sqlite3
import database_methods

host_name = "localhost"
port_num = 8080

rate_limit_lock = threading.Lock()
request_counts = {}
print(type(request_counts))

def convert_int_to_base64(int_value):
    hex_value = format(int_value, 'x')
    if len(hex_value) % 2 == 1:
        hex_value = '0' + hex_value
    byte_value = bytes.fromhex(hex_value)
    enc = base64.urlsafe_b64encode(byte_value).rstrip(b'=')
    return enc.decode('utf-8')

def rate_limit(ip):
    with rate_limit_lock:
        current_time = datetime.datetime.now()
        if ip not in request_counts:
            request_counts[ip] = []
        request_counts[ip] = [t for t in request_counts[ip] if t > current_time - datetime.timedelta(seconds=1)]
        if len(request_counts[ip]) >= 10:
            return True
        request_counts[ip].append(current_time)
        return False


database_methods.create_database()
database_methods.create_users_table()
database_methods.create_auth_table()
database_methods.create_enviroment_var()
key1 = database_methods.create_private_test_key()
expkey1 = database_methods.create_expired_test_key()
key1_content = key1[0]
expkey1_content = expkey1[0]
key1_expiration = key1[1]
expkey1_expiration = expkey1[1]
database_methods.save_private_key_to_db(key1_content, key1_expiration)
database_methods.save_private_key_to_db(expkey1_content, expkey1_expiration)

class Server(BaseHTTPRequestHandler): 
    def do_GET(self): 
        if self.path == "/.well-known/jwks.json": 
            self.send_response(200) 
            self.send_header("Content-type", "application/json")
            keys = database_methods.get_unexpired_keys()
            issued_keys = {
                "keys": [

                        ]
                         }
            for key in keys:
                RSA_key = RSA.import_key(key[0])
                kid_data = key[2]
                kid_string = str(kid_data)
                modulus = RSA_key.n
                exponent = RSA_key.e
                header = {
                            "alg": "RS256",
                            "kty": "RSA", 
                            "use": "sig",
                            "kid": kid_string,
                            "n": base64.urlsafe_b64encode(modulus.to_bytes((modulus.bit_length() + 7) // 8, byteorder='big')).decode(),
                            "e": base64.urlsafe_b64encode(exponent.to_bytes((exponent.bit_length() + 7) // 8, byteorder='big')).decode(),
                        }
                issued_keys["keys"].append(header)
            self.end_headers()     
            self.wfile.write(bytes(json.dumps(issued_keys), "utf-8"))
            return

        self.send_response(405)
        self.end_headers()
        return

    def do_POST(self):
        path = urlparse(self.path)
        parameters = parse_qs(path.query)
        if path.path == "/auth":
            request_ip = self.client_address[0]
            if rate_limit(request_ip):
                self.send_response(429)
                self.send_header('Content-type', 'text/plain')
                self.end_headers()
                self.wfile.write(bytes("Too Many Requests", "utf-8"))
                return
            request_timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            request_data = json.loads(post_data.decode('utf-8'))
            username = request_data.get("username", "")
            database_methods.save_auth_to_db(request_ip, request_timestamp, username)
            exp_key = database_methods.get_private_key_from_db(expired=False)
            if 'expired' in parameters:
                exp_key = database_methods.get_private_key_from_db(expired=True)
                kid_data = exp_key[2]
                kid_string = str(kid_data)
                header = {
                    "kid": kid_string
                }

                payload = {
                "user": "username",
                "exp": exp_key[1]
                } 
            else:
                exp_key = database_methods.get_private_key_from_db(expired=False)
                kid_data = exp_key[2]
                kid_string = str(kid_data)
                header = {
                    "kid": kid_string
                }
                payload = {
                "user": "username",
                "exp": exp_key[1]
                }
            pem = exp_key[0]
            ej = jwt.encode(payload, pem, algorithm="RS256", headers=header)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(bytes(ej, "utf-8"))
            return
        
        if path.path == "/register":
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            registration_data = json.loads(post_data.decode('utf-8'))
            
            username = registration_data.get("username")
            email = registration_data.get("email")
            
            if username and email:
                sec_pass = database_methods.generate_secure_password_UUIDv4()
                response_data = {"password": sec_pass}
                response_status = 201
                date_registered = datetime.datetime.now()
                last_login = datetime.datetime.now()
                password_hash = database_methods.hash_password_argon2(sec_pass)
                hashed = password_hash[0]
                database_methods.save_user_to_db(username, hashed, email, date_registered, last_login)

            else:
                response_data = {"error": "Invalid registration data"}
                response_status = 400

            self.send_response(response_status)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(response_data).encode('utf-8'))
            return

        self.send_response(405)
        self.end_headers()
        return 

if __name__ == "__main__":
    server = HTTPServer((host_name, port_num), Server)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    server.server_close()
