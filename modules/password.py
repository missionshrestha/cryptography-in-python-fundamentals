from zxcvbn import zxcvbn
import bcrypt

def check_password_strength(password):
    result = zxcvbn(password=password)
    score = result['score']
    if score > 3:
        return f"Strong password with score {score}"
    feedback = result['feedback']
    suggestions = feedback.get('suggestions', [])
    warning = feedback.get('warning', '')
    response = f"Weak password with score {score}.\n"
    if warning:
        response += f"Warning: {warning}\n"
    for suggestion in suggestions:
        response += f" - {suggestion}\n"
    return response


def hash_password(password):
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed

def verify_password(password, hashed):
    if bcrypt.checkpw(password.encode('utf-8'), hashed):
        return "Password is valid."
    return "Password is invalid."

if __name__ == "__main__":
    # test_passwords = [
    #     "password123",
    #     "P@ssw0rd!",
    #     "Tr0ub4dor&3"
    # ]
    # for pwd in test_passwords:
    #     print(f"Password: {pwd}")
    #     print(check_password_strength(pwd))
    #     print("-" * 40)

    while True:
        password = input("Enter a password to check its strength (or type 'exit' to quit): ")
        if password.lower() == 'exit':
            break
        print(check_password_strength(password))
        if check_password_strength(password).startswith("Weak"):
            print("Please choose a stronger password.")
        else:
            break

    hashed_pasword = hash_password(password)
    print(f"Hashed Password: {hashed_pasword}")
    confirm_password = input("Re-enter your password for verification: ")
    verification = verify_password(confirm_password, hashed_pasword)
    print(verification)