"""
Core Caesar Cipher implementation
Contains the fundamental cipher operations
"""

import string
from typing import Dict

class CaesarCipher:
    """Core Caesar Cipher implementation with basic operations"""
    
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
    
    def validate_shift(self, shift: int) -> bool:
        """Validate that shift is within acceptable range"""
        return 1 <= shift <= self.alphabet_size - 1
    
    def get_shift_range(self) -> range:
        """Get the valid range of shift values"""
        return range(1, self.alphabet_size)
