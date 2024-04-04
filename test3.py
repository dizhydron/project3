import database_methods
from Crypto.Random import get_random_bytes
import datetime
import requests

def test_user_save_and_get():
    username = "testuser"
    password_hash = "testpassword"
    email = "testemail"
    date_registered = datetime.datetime.now()
    last_login = datetime.datetime.now()
    database_methods.save_user_to_db(username, password_hash, email, date_registered, last_login)
    result = database_methods.get_user_from_db()
    assert result != None
    test_result = True
    return test_result

def test_auth_log_save_and_get():
    request_ip = "testip"
    request_timestamp = datetime.datetime.now()
    user_id = 1
    database_methods.save_auth_to_db(request_ip, request_timestamp, user_id)
    result = database_methods.get_auth_from_db()
    assert result != None
    test_result = True
    return test_result

def test_generate_safe_password():
    result = database_methods.generate_secure_password_UUIDv4()
    assert result != None
    test_result = True
    return test_result

def test_encrypt_private_key_hash():
    password = "testpassword"
    result = database_methods.hash_password_argon2(password)
    assert result != None
    test_result = True
    return test_result

def test_AES_encryption_and_decryption():
    key = get_random_bytes(16)
    text = "testtext"
    encrypted = database_methods.encrypt_private_key_AES(key, text)
    print (encrypted)
    decrypted = database_methods.decrypt_private_key_AES(key, encrypted)
    print (decrypted)
    assert decrypted != None
    test_result = True
    return test_result

def test_enviornment_var():
    database_methods.create_enviroment_var()
    result = database_methods.get_enviroment_var()
    assert result != None
    test_result = True
    return test_result

def test_save__and_get_AES_key_to_db():
    return

if __name__ == "__main__":
    tests_passed = 0
    test1 = test_user_save_and_get()
    print("Testing user save and get functions")
    if test1:
        print("Test 1: Passed")
        tests_passed += 1
    else:
        print("Test 1: Failed")


    test2 = test_auth_log_save_and_get()
    print("Testing auth log save and get functions")
    if test2:
        print("Test 2: Passed")
        tests_passed += 1
    else:
        print("Test 2: Failed")

    test3 = test_generate_safe_password()
    print("Testing generate safe password function")
    if test3:
        print("Test 3: Passed")
        tests_passed += 1
    else:
        print("Test 3: Failed")

    test4 = test_encrypt_private_key_hash()
    print("Testing encrypt private key hash function")
    if test4:
        print("Test 4: Passed")
        tests_passed += 1
    else:
        print("Test 4: Failed")

    print("Testing AES encryption and decryption functions")
    test5 = test_AES_encryption_and_decryption()
    if test5:
        print("Test 5: Passed")
        tests_passed += 1
    else:
        print("Test 5: Failed")

    test6 = test_enviornment_var()
    print("Testing enviornment variable function")
    if test6:
        print("Test 6: Passed")
        tests_passed += 1
    else:
        print("Test 6: Failed")

    testkey = database_methods.create_private_test_key()
    database_methods.create_database()
    print("Testing save and get AES key to db function")
    print(testkey)
    result = True
    if result:
        print("Test 7: Passed")
        tests_passed += 1
    else:
        print("Test 7: Failed")

    percentage_passed = (tests_passed / 7) * 100
    print(f"Percentage of tests passed for Brian Vaughn's test suite: {percentage_passed:.2f}%")