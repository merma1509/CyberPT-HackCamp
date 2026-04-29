"""
Caesar Cipher Educational Toolkit
A modular, educational cryptography learning system
"""

__version__ = "1.0.0"
__author__ = "Educational Cryptography Team"
__description__ = "Modular Caesar Cipher implementation with educational features"

# Import main classes for easy access
from .core import CaesarCipher
from .analysis import Cryptanalysis
from .education import Educational
from .ui import UserInterface

# Convenience function for quick usage
def quick_encrypt(text: str, shift: int) -> str:
    """Quick encrypt function"""
    cipher = CaesarCipher()
    return cipher.caesar_cipher(text, shift, 'encode')

def quick_decrypt(text: str, shift: int) -> str:
    """Quick decrypt function"""
    cipher = CaesarCipher()
    return cipher.caesar_cipher(text, shift, 'decode')

def quick_brute_force(ciphertext: str) -> dict:
    """Quick brute force function"""
    analysis = Cryptanalysis()
    return analysis.brute_force_decrypt(ciphertext)
