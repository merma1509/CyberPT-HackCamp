"""Caesar Cipher Implementation - Educational Cryptography Tool
   A classic substitution cipher with features for learning and demonstration
"""

import string
import random
from typing import Dict, List, Tuple
from collections import Counter

class CaesarCipher:
    """Caesar Cipher with educational features and analysis tools"""
    
    def __init__(self):
        self.alphabet_upper = string.ascii_uppercase
        self.alphabet_lower = string.ascii_lowercase
        self.alphabet_size = 26
    
    def caesar_cipher(self, text: str, shift: int, mode: str = 'encode') -> str:
        """
        Core Caesar Cipher implementation
        
        Args:
            text:  Input text to encode/decode
            shift: Number of positions to shift (1-25)
            mode:  'encode' or 'decode'
        
        Returns:
            Encoded/decoded text
        """
        if mode == 'decode':
            shift = -shift
        
        # Normalize shift to handle large numbers
        shift = shift % self.alphabet_size
        
        result = []
        
        for char in text:
            if char.isalpha():
                # Determine alphabet start based on case
                start = ord('A') if char.isupper() else ord('a')
                # Apply Caesar shift with modular arithmetic
                new_char = chr((ord(char) - start + shift) % self.alphabet_size + start)
                result.append(new_char)
            else:
                # Preserve non-alphabetic characters
                result.append(char)
        
        return ''.join(result)
    
    def brute_force_decrypt(self, ciphertext: str) -> Dict[int, str]:
        """
        Try all possible shifts to decrypt ciphertext
        
        Args:
            ciphertext: Encrypted text
        
        Returns:
            Dictionary mapping shift values to decrypted text
        """
        results = {}
        for shift in range(1, self.alphabet_size):
            decrypted = self.caesar_cipher(ciphertext, shift, mode='decode')
            results[shift] = decrypted
        return results
    
    def frequency_analysis(self, text: str) -> Dict[str, float]:
        """
        Perform frequency analysis on text
        
        Args:
            text: Text to analyze
        
        Returns:
            Dictionary of letter frequencies
        """
        # Filter only alphabetic characters and convert to uppercase
        filtered_text = ''.join([c.upper() for c in text if c.isalpha()])
        
        if not filtered_text:
            return {}
        
        # Count letter frequencies
        letter_counts = Counter(filtered_text)
        total_letters = len(filtered_text)
        
        # Calculate percentages
        frequencies = {letter: (count / total_letters) * 100 
                      for letter, count in letter_counts.items()}
        
        return frequencies
    
    def suggest_shift_by_frequency(self, ciphertext: str) -> List[Tuple[int, float]]:
        """
        Suggest likely shift values based on frequency analysis
        
        Args:
            ciphertext: Encrypted text
        
        Returns:
            List of (shift, confidence_score) tuples sorted by confidence
        """
        # English letter frequencies (approximate)
        english_freq = {
            'E': 12.7, 'T': 9.1, 'A': 8.2, 'O': 7.5, 'I': 7.0,
            'N': 6.7, 'S': 6.3, 'H': 6.1, 'R': 6.0, 'D': 4.3,
            'L': 4.0, 'U': 2.8, 'C': 2.8, 'M': 2.4, 'W': 2.4,
            'F': 2.2, 'G': 2.0, 'Y': 2.0, 'P': 1.9, 'B': 1.3,
            'V': 1.0, 'K': 0.8, 'J': 0.15, 'X': 0.15, 'Q': 0.10, 'Z': 0.07
        }
        
        # Analyze ciphertext frequency
        cipher_freq = self.frequency_analysis(ciphertext)
        
        if not cipher_freq:
            return []
        
        suggestions = []
        
        # Try each possible shift and calculate confidence
        for shift in range(1, self.alphabet_size):
            decrypted = self.caesar_cipher(ciphertext, shift, mode='decode')
            decrypted_freq = self.frequency_analysis(decrypted)
            
            # Calculate correlation with English frequencies
            correlation = 0
            for letter in english_freq:
                if letter in decrypted_freq:
                    correlation += abs(english_freq[letter] - decrypted_freq[letter])
            
            # Lower correlation = better match
            confidence = 100 - correlation
            suggestions.append((shift, confidence))
        
        # Sort by confidence (highest first)
        suggestions.sort(key=lambda x: x[1], reverse=True)
        return suggestions[:7]  # Return top 7 suggestions
    
    def analyze_shift_pattern(self, text: str) -> Dict[int, int]:
        """
        Analyze shift patterns in text (useful for Vigenère cipher detection)
        
        Args:
            text: Text to analyze
        
        Returns:
            Dictionary of shift frequencies
        """
        shifts = []
        
        for i in range(1, len(text)):
            if text[i].isalpha() and text[i-1].isalpha():
                # Calculate shift between consecutive letters
                if text[i].isupper() == text[i-1].isupper():
                    shift = (ord(text[i]) - ord(text[i-1])) % self.alphabet_size
                    if shift != 0:
                        shifts.append(shift)
        
        # Count shift frequencies
        shift_counts = Counter(shifts)
        return dict(shift_counts)
    
    def educational_demo(self) -> None:
        """Interactive educational demonstration of Caesar Cipher"""
        print("Caesar Cipher Educational Demo")
        print("=" * 50)
        
        # Example 1: Basic encryption/decryption
        print("\n1. Basic Encryption/Decryption:")
        message = "Hello, World 2026!"
        key = 3
        
        encrypted = self.caesar_cipher(message, key, 'encode')
        decrypted = self.caesar_cipher(encrypted, key, 'decode')
        
        print(f"Original:  {message}")
        print(f"Key:       {key}")
        print(f"Encrypted: {encrypted}")
        print(f"Decrypted: {decrypted}")
        
        # Example 2: Mathematical demonstration
        print("\n2. Mathematical Formula Demonstration:")
        print("Encryption: E_n(x) = (x + n) mod 26")
        print("Decryption: D_n(x) = (x - n) mod 26")
        print("\nWhere:")
        print("- x = letter position (A=0, B=1, ..., Z=25)")
        print("- n = shift value")
        print("- mod 26 = wrap around alphabet")
        
        # Example 3: Brute force demonstration
        print("\n3. Brute Force Attack Demonstration:")
        test_cipher = "Khoor, Zruog!"
        print(f"Ciphertext: {test_cipher}")
        print("\nPossible decryptions:")
        
        brute_results = self.brute_force_decrypt(test_cipher)
        for shift, result in brute_results.items():
            print(f"Shift {shift:2d}: {result}")
        
        # Example 4: Frequency analysis
        print("\n4. Frequency Analysis:")
        sample_text = "The quick brown fox jumps over the lazy dog"
        freq = self.frequency_analysis(sample_text)
        
        print(f"Sample text: {sample_text}")
        print("\nLetter frequencies:")
        for letter, percentage in sorted(freq.items()):
            print(f"{letter}: {percentage:.1f}%")
        
        # Example 5: Security limitations
        print("\n5. Security Limitations:")
        print("Caesar Cipher has major security weaknesses:")
        print("   • Only 25 possible keys (very small key space)")
        print("   • Vulnerable to brute force attacks")
        print("   • Vulnerable to frequency analysis")
        print("   • Preserves letter patterns and word lengths")
        print("   • Not suitable for modern security needs")
        
        print("\nEducational Value:")
        print("   • Teaches basic cryptographic concepts")
        print("   • Demonstrates modular arithmetic")
        print("   • Introduction to cryptanalysis")
        print("   • Foundation for understanding modern ciphers")

def interactive_cipher():
    """Interactive Caesar Cipher tool"""
    cipher = CaesarCipher()
    
    print("\nInteractive Caesar Cipher Tool")
    print("=" * 40)
    
    while True:
        print("\nOptions:")
        print("1. Encode message")
        print("2. Decode message")
        print("3. Brute force decrypt")
        print("4. Frequency analysis")
        print("5. Educational demo")
        print("6. Exit")
        
        choice = input("\nEnter your choice (1-6): ").strip()
        
        if choice == '1':
            text = input("Enter message to encode: ")
            try:
                shift = int(input("Enter shift value (1-25): "))
                if 1 <= shift <= 25:
                    result = cipher.caesar_cipher(text, shift, 'encode')
                    print(f"\nEncoded: {result}")
                else:
                    print("Shift must be between 1 and 25")
            except ValueError:
                print("Please enter a valid number")
        
        elif choice == '2':
            text = input("Enter message to decode: ")
            try:
                shift = int(input("Enter shift value (1-25): "))
                if 1 <= shift <= 25:
                    result = cipher.caesar_cipher(text, shift, 'decode')
                    print(f"\nDecoded: {result}")
                else:
                    print("Shift must be between 1 and 25")
            except ValueError:
                print("Please enter a valid number")
        
        elif choice == '3':
            text = input("Enter ciphertext to brute force: ")
            results = cipher.brute_force_decrypt(text)
            print("\nBrute force results:")
            for shift, result in results.items():
                print(f"Shift {shift:2d}: {result}")
        
        elif choice == '4':
            text = input("Enter text for frequency analysis: ")
            freq = cipher.frequency_analysis(text)
            if freq:
                print("\nLetter frequencies:")
                for letter, percentage in sorted(freq.items()):
                    print(f"{letter}: {percentage:.1f}%")
                
                # Suggest shifts
                suggestions = cipher.suggest_shift_by_frequency(text)
                if suggestions:
                    print("\nLikely shift values (based on frequency analysis):")
                    for shift, confidence in suggestions:
                        print(f"Shift {shift:2d}: {confidence:.1f}% confidence")
            else:
                print("No alphabetic characters found")
        
        elif choice == '5':
            cipher.educational_demo()
        
        elif choice == '6':
            print("Goodbye!")
            break
        
        else:
            print("Invalid choice. Please enter 1-6.")

if __name__ == "__main__":
    # Run interactive tool
    interactive_cipher()
