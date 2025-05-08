"""
File: 
Description:
Author: 0x6D76
Copyright (c) 2025 0x6d76@proton.me
"""
import configparser
import os
import sys

def LoadConfig (config_file):
    """Loads configuration from the given INI file."""
    current_dir = os.path.dirname(os.path.abspath(__file__))
    config_file = os.path.join(current_dir, config_file)
    config = configparser.ConfigParser ()
    try:
        config.read (config_file)
        return config
    except configparser.Error as e:
        print (f"Error reading configuration file: {e}")
        sys.exit (1)  # Exit if configuration cannot be loaded
    except Exception as e:
        print (f"An unexpected error occurred loading config: {e}")
        sys.exit (1)