"""
Educational components for Caesar Cipher
Contains demonstrations, examples, and learning materials
"""

from core import CaesarCipher
from analysis import Cryptanalysis

class Educational:
    """Educational demonstrations and learning materials"""
    
    def __init__(self):
        self.cipher = CaesarCipher()
        self.analysis = Cryptanalysis()
    
    def basic_encryption_demo(self) -> None:
        """Demonstrate basic encryption/decryption"""
        print("Basic Encryption/Decryption:")
        message = "Hello, World 2026!"
        key = 3
        
        encrypted = self.cipher.caesar_cipher(message, key, 'encode')
        decrypted = self.cipher.caesar_cipher(encrypted, key, 'decode')
        
        print(f"Original:  {message}")
        print(f"Key:       {key}")
        print(f"Encrypted: {encrypted}")
        print(f"Decrypted: {decrypted}")
    
    def mathematical_formula_demo(self) -> None:
        """Explain the mathematical foundation"""
        print("\nMathematical Formula:")
        print("Encryption: E_n(x) = (x + n) mod 26")
        print("Decryption: D_n(x) = (x - n) mod 26")
        print("\nWhere:")
        print("- x = letter position (A=0, B=1, ..., Z=25)")
        print("- n = shift value")
        print("- mod 26 = wrap around alphabet")
        
        # Example calculation
        print("\nExample: Encrypt 'A' with shift 3")
        print("x = 0 (position of 'A')")
        print("n = 3")
        print("E(0) = (0 + 3) mod 26 = 3")
        print("Position 3 = 'D'")
        print("So 'A' → 'D'")
    
    def brute_force_demo(self) -> None:
        """Demonstrate brute force attack"""
        print("\nBrute Force Attack:")
        test_cipher = "Khoor, Zruog!"
        print(f"Ciphertext: {test_cipher}")
        print("\nPossible decryptions:")
        
        brute_results = self.analysis.brute_force_decrypt(test_cipher)
        for shift, result in brute_results.items():
            print(f"Shift {shift:2d}: {result}")
    
    def frequency_analysis_demo(self) -> None:
        """Demonstrate frequency analysis"""
        print("\nFrequency Analysis:")
        sample_text = "The quick brown fox jumps over the lazy dog"
        freq = self.analysis.frequency_analysis(sample_text)
        
        print(f"Sample text: {sample_text}")
        print("\nLetter frequencies:")
        for letter, percentage in sorted(freq.items()):
            print(f"{letter}: {percentage:.1f}%")
    
    def security_limitations(self) -> None:
        """Explain security limitations"""
        print("\nSecurity Limitations:")
        print("Caesar Cipher has major security weaknesses:")
        print("   • Only 25 possible keys (very small key space)")
        print("   • Vulnerable to brute force attacks")
        print("   • Vulnerable to frequency analysis")
        print("   • Preserves letter patterns and word lengths")
        print("   • Not suitable for modern security needs")
        
        print("\n✅ Educational Value:")
        print("   • Teaches basic cryptographic concepts")
        print("   • Demonstrates modular arithmetic")
        print("   • Introduction to cryptanalysis")
        print("   • Foundation for understanding modern ciphers")
    
    def historical_context(self) -> None:
        """Provide historical context"""
        print("\n📚 Historical Context:")
        print("Julius Caesar (100-44 BCE)")
        print("- Used this cipher for military communications")
        print("- Shift of 3 was his standard")
        print("- Protected messages from casual observers")
        
        print("\nOther Historical Uses:")
        print("- Roman military: tactical messages")
        print("- Medieval cryptography: simple secret messages")
        print("- Civil War: basic battlefield communication")
        print("- Early computer science: teaching tool")
    
    def modern_applications(self) -> None:
        """Show modern educational applications"""
        print("\n🎓 Modern Educational Applications:")
        print("1. Computer Science Education:")
        print("   - Teaching string manipulation")
        print("   - Introduction to ASCII/Unicode")
        print("   - Understanding modular arithmetic")
        
        print("\n2. Cryptography Fundamentals:")
        print("   - Basic encryption concepts")
        print("   - Symmetric key cryptography")
        print("   - Cryptanalysis techniques")
        
        print("\n3. Programming Practice:")
        print("   - Loop and conditional logic")
        print("   - Character encoding/decoding")
        print("   - Algorithm implementation")
        
        print("\n4. Security Awareness:")
        print("   - Demonstrates weak encryption")
        print("   - Importance of key space")
        print("   - Need for modern ciphers")
    
    def comparison_with_modern_ciphers(self) -> None:
        """Compare with modern encryption"""
        print("\n🔐 Comparison with Modern Ciphers:")
        print("Caesar Cipher vs AES (Advanced Encryption Standard):")
        
        comparison_data = [
            ("Key Space", "25 possibilities", "2^256 possibilities"),
            ("Security Level", "None (trivially breakable)", "Military-grade secure"),
            ("Key Length", "5 bits (log₂25)", "256 bits"),
            ("Attack Resistance", "Brute force in milliseconds", "Quantum-resistant"),
            ("Use Case", "Educational only", "Real-world encryption"),
            ("Complexity", "Simple modular arithmetic", "Complex mathematical operations")
        ]
        
        for aspect, caesar, aes in comparison_data:
            print(f"{aspect:20} | Caesar: {caesar:30} | AES: {aes}")
        
        print("\nKey Takeaway:")
        print("Caesar Cipher is valuable for learning but completely inadequate")
        print("for modern security needs. Always use industry-standard encryption")
        print("like AES for real-world applications.")
    
    def run_complete_demo(self) -> None:
        """Run complete educational demonstration"""
        print("Caesar Cipher Educational Demo")
        print("=" * 50)
        
        self.basic_encryption_demo()
        self.mathematical_formula_demo()
        self.brute_force_demo()
        self.frequency_analysis_demo()
        self.security_limitations()
        self.historical_context()
        self.modern_applications()
        self.comparison_with_modern_ciphers()
