import json
import re
import random
import string

def caesar_encrypt(text, shift):
    encrypted_text = ""
    for char in text:
        if char.isalpha():
            shifted = ord(char) + shift
            if char.islower():
                if shifted > ord('z'):
                    shifted -= 26
            elif char.isupper():
                if shifted > ord('Z'):
                    shifted -= 26
            encrypted_text += chr(shifted)
        else:
            encrypted_text += char
    return encrypted_text

def caesar_decrypt(text, shift):
    return caesar_encrypt(text, -shift)

def is_strong_password(password):
    """
    Check if the password is strong.
    Strong password = at least 8 chars, upper, lower, digit, special char.
    """
    if (len(password) >= 8
        and re.search("[A-Z]", password)
        and re.search("[a-z]", password)
        and re.search("[0-9]", password)
        and re.search("[!@#$%^&*()_+=-]", password)):
        return True
    return False

def generate_password(length):
    """
    Generate a random strong password of the specified length.
    """
    characters = string.ascii_letters + string.digits + "!@#$%^&*()_+=-"
    return "".join(random.choice(characters) for _ in range(length))

encrypted_passwords = []
websites = []
usernames = []

SHIFT = 3

def add_password():
    print("\nAdd a new password")

    website = input("Website: ")
    username = input("Username: ")

    pw_choice = input("Do you want to generate a random strong password? (y/n): ")

    if pw_choice.lower() == "y":
        length = int(input("Password length: "))
        password = generate_password(length)
        print("Generated password:", password)
    else:
        password = input("Password: ")

        if not is_strong_password(password):
            print("Warning: password is weak (short or missing character types).")

    encrypted = caesar_encrypt(password, SHIFT)

    websites.append(website)
    usernames.append(username)
    encrypted_passwords.append(encrypted)

    print("Password added!")

def get_password():
    print("\nRetrieve password")

    website = input("Enter website: ")

    if website in websites:
        index = websites.index(website)
        username = usernames[index]
        encrypted_pw = encrypted_passwords[index]
        decrypted_pw = caesar_decrypt(encrypted_pw, SHIFT)

        print(f"Website: {website}")
        print(f"Username: {username}")
        print(f"Password: {decrypted_pw}")
    else:
        print("No password stored for this website.")

def save_passwords():
    print("\nSaving passwords...")

    data = {
        "websites": websites,
        "usernames": usernames,
        "passwords": encrypted_passwords
    }

    with open("vault.txt", "w") as f:
        json.dump(data, f)

    print("Passwords saved to vault.txt!")

def load_passwords():
    print("\nLoading passwords...")

    global websites, usernames, encrypted_passwords

    try:
        with open("vault.txt", "r") as f:
            data = json.load(f)

        websites = data.get("websites", [])
        usernames = data.get("usernames", [])
        encrypted_passwords = data.get("passwords", [])

        print("Vault loaded successfully!")

    except FileNotFoundError:
        print("vault.txt not found. No passwords loaded.")

    except json.JSONDecodeError:
        print("Error: vault.txt is corrupted or unreadable.")

def main():

    while True:
        print("\nPassword Manager Menu:")
        print("1. Add Password")
        print("2. Get Password")
        print("3. Save Passwords")
        print("4. Load Passwords")
        print("5. Quit")
        
        choice = input("Enter your choice: ")
        
        if choice == "1":
            add_password()
        elif choice == "2":
            get_password()
        elif choice == "3":
            save_passwords()
        elif choice == "4":
            load_passwords()
        elif choice == "5":
            break
        else:
            print("Invalid choice. Please try again.")


if __name__ == "__main__":
    main()
