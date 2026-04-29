"""
Cryptanalysis tools for Caesar Cipher
Contains frequency analysis, brute force, and pattern detection
"""

from typing import Dict, List, Tuple
from collections import Counter

from core import CaesarCipher

class Cryptanalysis:
    """Cryptanalysis tools for Caesar Cipher"""
    
    def __init__(self):
        self.cipher = CaesarCipher()
        # English letter frequencies (approximate)
        self.english_freq = {
            'E': 12.7, 'T': 9.1, 'A': 8.2, 'O': 7.5, 'I': 7.0,
            'N': 6.7, 'S': 6.3, 'H': 6.1, 'R': 6.0, 'D': 4.3,
            'L': 4.0, 'U': 2.8, 'C': 2.8, 'M': 2.4, 'W': 2.4,
            'F': 2.2, 'G': 2.0, 'Y': 2.0, 'P': 1.9, 'B': 1.3,
            'V': 1.0, 'K': 0.8, 'J': 0.15, 'X': 0.15, 'Q': 0.10, 'Z': 0.07
        }
    
    def brute_force_decrypt(self, ciphertext: str) -> Dict[int, str]:
        """
        Try all possible shifts to decrypt ciphertext
        
        Args:
            ciphertext: Encrypted text
        
        Returns:
            Dictionary mapping shift values to decrypted text
        """
        results = {}
        for shift in self.cipher.get_shift_range():
            decrypted = self.cipher.caesar_cipher(ciphertext, shift, mode='decode')
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
        # Analyze ciphertext frequency
        cipher_freq = self.frequency_analysis(ciphertext)
        
        if not cipher_freq:
            return []
        
        suggestions = []
        
        # Try each possible shift and calculate confidence
        for shift in self.cipher.get_shift_range():
            decrypted = self.cipher.caesar_cipher(ciphertext, shift, mode='decode')
            decrypted_freq = self.frequency_analysis(decrypted)
            
            # Calculate correlation with English frequencies
            correlation = 0
            for letter in self.english_freq:
                if letter in decrypted_freq:
                    correlation += abs(self.english_freq[letter] - decrypted_freq[letter])
            
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
                    shift = (ord(text[i]) - ord(text[i-1])) % 26
                    if shift != 0:
                        shifts.append(shift)
        
        # Count shift frequencies
        shift_counts = Counter(shifts)
        return dict(shift_counts)
    
    def detect_english_like(self, text: str) -> float:
        """
        Calculate how English-like the text appears based on frequency analysis
        
        Args:
            text: Text to analyze
        
        Returns:
            Score between 0-100 indicating English similarity
        """
        freq = self.frequency_analysis(text)
        if not freq:
            return 0.0
        
        # Calculate correlation with English frequencies
        correlation = 0
        for letter in self.english_freq:
            if letter in freq:
                correlation += abs(self.english_freq[letter] - freq[letter])
        
        # Convert to similarity score (lower correlation = higher similarity)
        similarity = max(0, 100 - correlation)
        return similarity
