"""
User Interface components for Caesar Cipher
Contains interactive CLI and menu systems
"""

from core import CaesarCipher
from analysis import Cryptanalysis
from education import Educational

class UserInterface:
    """Interactive user interface for Caesar Cipher"""
    
    def __init__(self):
        self.cipher = CaesarCipher()
        self.analysis = Cryptanalysis()
        self.education = Educational()
    
    def get_user_input(self, prompt: str, input_type: type = str) -> any:
        """Get validated user input"""
        while True:
            try:
                user_input = input(prompt).strip()
                if input_type == int:
                    return int(user_input)
                return user_input
            except ValueError:
                print(f"Please enter a valid {input_type.__name__}")
    
    def encode_message(self) -> None:
        """Handle message encoding"""
        text = self.get_user_input("Enter message to encode: ")
        shift = self.get_user_input("Enter shift value (1-25): ", int)
        
        if self.cipher.validate_shift(shift):
            result = self.cipher.caesar_cipher(text, shift, 'encode')
            print(f"\nEncrypted: {result}")
        else:
            print("Shift must be between 1 and 25")
    
    def decode_message(self) -> None:
        """Handle message decoding"""
        text = self.get_user_input("Enter message to decode: ")
        shift = self.get_user_input("Enter shift value (1-25): ", int)
        
        if self.cipher.validate_shift(shift):
            result = self.cipher.caesar_cipher(text, shift, 'decode')
            print(f"\nDecoded: {result}")
        else:
            print("Shift must be between 1 and 25")
    
    def brute_force_attack(self) -> None:
        """Handle brute force attack"""
        text = self.get_user_input("Enter ciphertext to brute force: ")
        results = self.analysis.brute_force_decrypt(text)
        
        print("\nBrute force results:")
        for shift, result in results.items():
            print(f"Shift {shift:2d}: {result}")
    
    def frequency_analysis_tool(self) -> None:
        """Handle frequency analysis"""
        text = self.get_user_input("Enter text for frequency analysis: ")
        freq = self.analysis.frequency_analysis(text)
        
        if freq:
            print("\nLetter frequencies:")
            for letter, percentage in sorted(freq.items()):
                print(f"{letter}: {percentage:.1f}%")
            
            # Suggest shifts
            suggestions = self.analysis.suggest_shift_by_frequency(text)
            if suggestions:
                print("\nLikely shift values (based on frequency analysis):")
                for shift, confidence in suggestions:
                    print(f"Shift {shift:2d}: {confidence:.1f}% confidence")
        else:
            print("No alphabetic characters found")
    
    def educational_demo(self) -> None:
        """Run educational demonstration"""
        self.education.run_complete_demo()
    
    def show_menu(self) -> None:
        """Display main menu"""
        print("\nCaesar Cipher Tool")
        print("=" * 30)
        print("1. Encode message")
        print("2. Decode message")
        print("3. Brute force decrypt")
        print("4. Frequency analysis")
        print("5. Educational demo")
        print("6. Exit")
        print("=" * 30)
    
    def run_interactive(self) -> None:
        """Run interactive CLI tool"""
        print("Welcome to the Caesar Cipher Educational Tool!")
        
        while True:
            self.show_menu()
            choice = self.get_user_input("\nEnter your choice (1-6): ")
            
            if choice == '1':
                self.encode_message()
            elif choice == '2':
                self.decode_message()
            elif choice == '3':
                self.brute_force_attack()
            elif choice == '4':
                self.frequency_analysis_tool()
            elif choice == '5':
                self.educational_demo()
            elif choice == '6':
                print("Goodbye!")
                break
            else:
                print("Invalid choice. Please enter 1-6.")
            
            input("\nPress Enter to continue...")
