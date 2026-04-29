"""Demonstrating Caesar Cipher features"""

from core import CaesarCipher
from analysis import Cryptanalysis
from education import Educational

def basic_examples():
    """Basic Caesar Cipher examples"""
    print("Basic Caesar Cipher Examples")
    print("=" * 20)
    
    cipher = CaesarCipher()
    
    # Example 1: Classic Caesar shift
    message = "HELLO WORLD"
    shift = 3
    
    encrypted = cipher.caesar_cipher(message, shift, 'encode')
    decrypted = cipher.caesar_cipher(encrypted, shift, 'decode')
    
    print(f"Original: {message}")
    print(f"Shift: {shift}")
    print(f"Encrypted: {encrypted}")
    print(f"Decrypted: {decrypted}")
    print()
    
    # Example 2: Different shift values
    message = "Python Programming"
    shifts = [1, 5, 13, 25]
    
    print("Different shift values:")
    for shift in shifts:
        encrypted = cipher.caesar_cipher(message, shift, 'encode')
        print(f"Shift {shift:2d}: {encrypted}")
    print()

def security_demonstration():
    """Demonstrate security weaknesses"""
    print("Security Weaknesses Demonstration")
    print("=" * 25)
    
    cipher = CaesarCipher()
    analysis = Cryptanalysis()
    
    # Sample encrypted message
    secret_message = "Meet me at midnight"
    encrypted = cipher.caesar_cipher(secret_message, 7, 'encode')
    
    print(f"Original message: {secret_message}")
    print(f"Encrypted with shift 7: {encrypted}")
    print()
    
    # Brute force attack
    print("Brute force attack results:")
    results = analysis.brute_force_decrypt(encrypted)
    
    for shift, result in results.items():
        if "meet" in result.lower() or "at" in result.lower():
            print(f"Shift {shift}: {result} (LIKELY CORRECT)")
        else:
            print(f"Shift {shift}: {result}")
    print()

def frequency_analysis_demo():
    """Demonstrate frequency analysis attack"""
    print("Frequency Analysis Attack")
    print("=" * 15)
    
    cipher = CaesarCipher()
    analysis = Cryptanalysis()
    
    # Longer text for better frequency analysis
    plaintext = """
    The quick brown fox jumps over the lazy dog. 
    This pangram contains all letters of the alphabet.
    Frequency analysis can help break simple ciphers.
    """
    
    # Encrypt with unknown shift
    unknown_shift = 15
    ciphertext = cipher.caesar_cipher(plaintext, unknown_shift, 'encode')
    
    print(f"Original text (first 50 chars): {plaintext[:50]}...")
    print(f"Encrypted with shift {unknown_shift}: {ciphertext[:50]}...")
    print()
    
    # Frequency analysis
    print("Frequency analysis results:")
    suggestions = analysis.suggest_shift_by_frequency(ciphertext)
    
    for i, (shift, confidence) in enumerate(suggestions, 1):
        decrypted = cipher.caesar_cipher(ciphertext, shift, 'decode')
        print(f"{i}. Shift {shift} (confidence: {confidence:.1f}%): {decrypted[:50]}...")
        
        if shift == unknown_shift:
            print("   → CORRECT SHIFT FOUND!")
    print()

def cryptanalysis_comparison():
    """Compare different cryptanalysis methods"""
    print("Cryptanalysis Methods Comparison")
    print("=" * 25)
    
    cipher = CaesarCipher()
    analysis = Cryptanalysis()
    
    # Test message
    original = "The secret message is hidden here"
    shift = 8
    ciphertext = cipher.caesar_cipher(original, shift, 'encode')
    
    print(f"Original: {original}")
    print(f"Encrypted (shift {shift}): {ciphertext}")
    print()
    
    # Method 1: Brute Force
    print("1. Brute Force Attack:")
    brute_results = analysis.brute_force_decrypt(ciphertext)
    english_scores = []
    
    for test_shift, result in brute_results.items():
        score = analysis.detect_english_like(result)
        english_scores.append((test_shift, score))
    
    # Sort by English similarity
    english_scores.sort(key=lambda x: x[1], reverse=True)
    
    print("Top 3 most English-like results:")
    for i, (test_shift, score) in enumerate(english_scores[:3], 1):
        result = brute_results[test_shift]
        print(f"  {i}. Shift {test_shift} (score: {score:.1f}): {result}")
    print()
    
    # Method 2: Frequency Analysis
    print("2. Frequency Analysis:")
    freq_suggestions = analysis.suggest_shift_by_frequency(ciphertext)
    
    print("Top 3 frequency-based suggestions:")
    for i, (test_shift, confidence) in enumerate(freq_suggestions[:3], 1):
        result = brute_results[test_shift]
        print(f"  {i}. Shift {test_shift} (confidence: {confidence:.1f}%): {result}")
    print()
    
    # Show which method was correct
    print(f"Actual shift was: {shift}")
    brute_correct = next((i for i, (s, _) in enumerate(english_scores[:3], 1) if s == shift), None)
    freq_correct = next((i for i, (s, _) in enumerate(freq_suggestions[:3], 1) if s == shift), None)
    
    print(f"Brute force found correct shift in top 3: {'Yes' if brute_correct else 'No'}")
    print(f"Frequency analysis found correct shift in top 3: {'Yes' if freq_correct else 'No'}")

def run_all_examples():
    """Run all example demonstrations"""
    print("Caesar Cipher Comprehensive Examples")
    print("=" * 25)
    print()
    
    basic_examples()
    security_demonstration()
    frequency_analysis_demo()
    cryptanalysis_comparison()
    
    print("Summary:")
    print("These examples demonstrate the Caesar Cipher's functionality,")
    print("security weaknesses, and how cryptanalysis can break it.")
    print("While educational, it highlights why modern encryption is essential.")

if __name__ == "__main__":
    run_all_examples()
