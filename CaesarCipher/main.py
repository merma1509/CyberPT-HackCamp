"""
Main entry point for Caesar Cipher application
"""

from ui import UserInterface

def main():
    """Main application entry point"""
    ui = UserInterface()
    ui.run_interactive()

if __name__ == "__main__":
    main()
