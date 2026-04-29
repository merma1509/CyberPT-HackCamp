"""Password generation utilities for Password Manager
   Handles secure random password generation with configurable options"""

import secrets
import string
from typing import Optional

from config import settings

class PasswordGenerator:
    """Generates secure random passwords with configurable complexity"""
    
    def __init__(self):
        self.default_length = settings.get_default_password_length()
    
    def generate_password(self, 
                        length: Optional[int] = None,
                        use_uppercase: bool = True,
                        use_lowercase: bool = True,
                        use_digits: bool = True,
                        use_symbols: bool = True,
                        exclude_ambiguous: bool = True) -> str:
        """
        Generate a secure random password with configurable complexity
        
        Args:
            length: Password length (default from config)
            use_uppercase: Include uppercase letters
            use_lowercase: Include lowercase letters
            use_digits: Include digits
            use_symbols: Include symbols
            exclude_ambiguous: Exclude ambiguous characters (ilLI1oO0)
        
        Returns:
            Generated password string
        """
        if length is None:
            length = self.default_length
        
        # Build character set
        chars = ""
        if use_lowercase:
            chars += string.ascii_lowercase
        if use_uppercase:
            chars += string.ascii_uppercase
        if use_digits:
            chars += string.digits
        if use_symbols:
            chars += "!@#$%^&*()_+-=[]{}|;:,.<>?"
        
        # Exclude ambiguous characters if requested
        if exclude_ambiguous:
            ambiguous = "ilLI1oO0"
            chars = ''.join(c for c in chars if c not in ambiguous)
        
        if not chars:
            raise ValueError("At least one character type must be selected")
        
        # Generate password
        password = ''.join(secrets.choice(chars) for _ in range(length))
        return password
    
    def generate_strong_password(self, length: Optional[int] = None) -> str:
        """Generate a strong password with all character types"""
        return self.generate_password(
            length=length,
            use_uppercase=True,
            use_lowercase=True,
            use_digits=True,
            use_symbols=True,
            exclude_ambiguous=True
        )
    
    def generate_memorable_password(self, word_count: int = 4) -> str:
        """Generate a memorable password using word-based approach"""
        # Simple word list for memorable passwords
        words = [
            'apple', 'banana', 'coffee', 'dragon', 'elephant', 'forest', 'guitar',
            'house', 'island', 'jungle', 'kitten', 'lemon', 'mountain', 'ocean',
            'piano', 'queen', 'river', 'sunset', 'tiger', 'umbrella', 'village',
            'window', 'yellow', 'zebra', 'butterfly', 'castle', 'diamond',
            'emerald', 'fountain', 'garden', 'horizon', 'island', 'journey'
        ]
        
        selected_words = [secrets.choice(words) for _ in range(word_count)]
        
        # Add numbers and symbols for complexity
        password = ''.join(word.capitalize() for word in selected_words)
        password += str(secrets.randbelow(100))
        password += secrets.choice("!@#$%^&*")
        
        return password
    
    def check_password_strength(self, password: str) -> dict:
        """
        Check password strength and return analysis
        
        Args:
            password: Password to analyze
        
        Returns:
            Dictionary with strength analysis
        """
        strength_score = 0
        feedback = []
        
        # Length check
        if len(password) >= 12:
            strength_score += 2
        elif len(password) >= 8:
            strength_score += 1
        else:
            feedback.append("Password should be at least 8 characters long")
        
        # Character variety checks
        if any(c.islower() for c in password):
            strength_score += 1
        else:
            feedback.append("Include lowercase letters")
        
        if any(c.isupper() for c in password):
            strength_score += 1
        else:
            feedback.append("Include uppercase letters")
        
        if any(c.isdigit() for c in password):
            strength_score += 1
        else:
            feedback.append("Include numbers")
        
        if any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
            strength_score += 1
        else:
            feedback.append("Include special characters")
        
        # Determine strength level
        if strength_score >= 5:
            strength = "Very Strong"
        elif strength_score >= 4:
            strength = "Strong"
        elif strength_score >= 3:
            strength = "Medium"
        elif strength_score >= 2:
            strength = "Weak"
        else:
            strength = "Very Weak"
        
        return {
            'strength': strength,
            'score': strength_score,
            'max_score': 6,
            'feedback': feedback
        }

# Global password generator instance
password_generator = PasswordGenerator()
