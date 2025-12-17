import json
import re
import random
import string

# Korjattu Caesar-salausta ja -purkua, jotta negatiivinen siirto toimii oikein
def caesar_encrypt(text, shift):
    encrypted_text = ""
    for char in text:
        if char.isalpha():
            shifted = ord(char) + shift

            if char.islower():
                if shifted > ord('z'):
                    shifted -= 26
                elif shifted < ord('a'):
                    shifted += 26

            elif char.isupper():
                if shifted > ord('Z'):
                    shifted -= 26
                elif shifted < ord('A'):
                    shifted += 26

            encrypted_text += chr(shifted)
        else:
            encrypted_text += char
    return encrypted_text

def caesar_decrypt(text, shift):
    return caesar_encrypt(text, -shift)

# Tarkistaa salasanan vahvuuden
def is_strong_password(password):
    return (len(password) >= 8
        and re.search("[A-Z]", password)
        and re.search("[a-z]", password)
        and re.search("[0-9]", password)
        and re.search("[!@#$%^&*()_+=-]", password))

# Generoi satunnaisen vahvan salasanan
def generate_password(length):
    characters = string.ascii_letters + string.digits + "!@#$%^&*()_+=-"
    return "".join(random.choice(characters) for _ in range(length))

encrypted_passwords = []
websites = []
usernames = []

SHIFT = 3

# Lisää uusi salasana
def add_password():
    print("\nAdd a new password")

    website = input("Website: ")
    username = input("Username: ")

    pw_choice = input("Do you want to generate a random strong password? (y/n): ")

    if pw_choice.lower() == "y":
        while True:
            try:
                length = int(input("Password length (min. 8 characters): "))
                if length >= 8:
                    break
                else:
                    print("Password must be at least 8 characters long. Please try again.")
            except ValueError:
                print("Password must be at least 8 characters. Please try again.")
        password = generate_password(length)
        print("Generated password:", password)
    else:
        password = input("Password: ")

        if not is_strong_password(password):
            print("Warning: password may be weak.")

    encrypted = caesar_encrypt(password, SHIFT)
    websites.append(website)
    usernames.append(username)
    encrypted_passwords.append(encrypted)

    print("Password added!")

# Hakee salasanan verkkosivun perusteella
def get_password():
    print("\nRetrieve password")
    website = input("Enter website: ")

    found = False
    for i, site in enumerate(websites):
        if site == website:
            found = True
            username = usernames[i]
            encrypted_pw = encrypted_passwords[i]
            decrypted_pw = caesar_decrypt(encrypted_pw, SHIFT)

            print(f"\nUsername: {username}")    # Alussa tyhjä rivi erottamaan eri käyttäjätunnukset
            print(f"Password: {decrypted_pw}")
    if not found:
        print("No password stored for this website.")

# Tallentaa salasanat tiedostoon
def save_passwords():
    print("\nSaving passwords...")

    data = {
        "websites": websites,
        "usernames": usernames,
        "passwords": encrypted_passwords
    }

    try:
        with open("vault.txt", "w") as f:
            json.dump(data, f)
        print("Passwords saved to vault.txt!")
    except PermissionError:
        print("Error: Cannot write to vault.txt")

# Palautetaan data tai None, jotta latauksen onnistuminen voidaan tarkistaa
def load_passwords():
    print("\nLoading passwords...")

    global websites, usernames, encrypted_passwords

    try:
        with open("vault.txt", "r") as f:
            data = json.load(f)

        websites = data.get("websites", [])
        usernames = data.get("usernames", [])
        encrypted_passwords = data.get("passwords", [])
        return data

    except FileNotFoundError:
        print("Error: vault.txt not found. No passwords loaded.")
        return None

    except json.JSONDecodeError:
        print("Error: vault.txt is corrupted or unreadable.")
        return None

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
            passwords = load_passwords()
            if passwords is not None:
                print("Passwords loaded successfully!")
        elif choice == "5":
            break
        else:
            print("Invalid choice. Please try again.")


if __name__ == "__main__":
    main()
