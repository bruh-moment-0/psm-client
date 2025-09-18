"""
# === testing ===
if __name__ == "__main__":
    # Test user creation and loading
    try:
        udc = create_user("john", "super-secret-password!")
        print("User created successfully")
        print(f"Username: {udc['username']}")
        print(f"Public Key (Kyber): {udc['publickey_kyber_b64']}...")
        print("\n"*2)
    except Exception as e:
        print(f"User creation error: {e}")
    try:
        udc = create_user("alice", "super-secret-password!")
        print("User created successfully")
        print(f"Username: {udc['username']}")
        print(f"Public Key (Kyber): {udc['publickey_kyber_b64'][:50]}...")
        print("\n"*2)
    except Exception as e:
        print(f"User creation error: {e}")

    try:
        udl = load_user("john", "super-secret-password!")
        print("User loaded successfully")
        print(f"Username: {udl['username']}")
        print(f"User Type: {udl['usertype']}")
        
        # Test token creation
        tok = create_token(udl)
        print(f"Token created successfully")
        print(f"Token expires at: {tok['exp']}")
        print("\n"*2)
        
        # Test messaging workflow with automatic token management
        print("Testing messaging workflow with automatic token management...")
        try:
            userdata = load_user("john", "super-secret-password!")
            token_data = create_token(userdata)
            token = token_data["tokens"]["access_token"]
            print(f"Authenticated as: {userdata['username']}")
            print(f"Initial token expires at: {token_data['exp']}")
            receiver = "alice"
            message = "Hello Alice! This is an encrypted message with automatic token management."
            print(f"\nSending message to {receiver}...")
            send_result = send_message(userdata, receiver, message, token)
            print(f"Message sent! ID: {send_result['message_id']}")
            print(f"Token expires at: {send_result['token_exp']}")
            print(f"\nRetrieving message {send_result['message_id']}...")
            alice_data = load_user("alice", "super-secret-password!")
            alice_token_data = create_token(alice_data)
            alice_token = alice_token_data["tokens"]["access_token"]
            retrieved_message = get_message(send_result['message_id'], alice_data, alice_token)
            print(f"Retrieved message: {retrieved_message['message']}")
            print(f"From: {retrieved_message['sender']}")
            print(f"Timestamp: {retrieved_message['timestamp']}")
            print(f"\nChecking token expiration...")
            exp_time = check_token_expiration(token)
            if exp_time:
                print(f"Token expires at: {exp_time}")
                print(f"Will expire soon: {is_token_expiring_soon(token)}")
            else:
                print("Token is invalid")
        except Exception as e:
            print(f"Error in messaging workflow: {e}")
        
    except Exception as e:
        print(f"User loading/messaging error: {e}")
"""