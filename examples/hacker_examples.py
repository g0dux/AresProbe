#!/usr/bin/env python3
"""
AresProbe Hacker Edition - Usage Examples
Demonstrates various attack scenarios and configurations
"""

import asyncio
import sys
from pathlib import Path

# Add the project root to Python path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from aresprobe.core.engine import AresEngine, ScanConfig, ScanType
from aresprobe.core.hacker_engine import HackerEngine, AttackMode
from aresprobe.core.logger import Logger

async def example_ultimate_hack():
    """Example of ultimate hack attack"""
    print("ULTIMATE HACK EXAMPLE")
    print("=" * 50)
    
    logger = Logger()
    hacker_engine = HackerEngine(logger)
    
    # Set attack mode
    hacker_engine.set_attack_mode(AttackMode.AGGRESSIVE)
    
    # Execute ultimate hack
    target = "https://example.com"
    results = await hacker_engine.execute_ultimate_attack(target, AttackMode.AGGRESSIVE)
    
    print(f"Target: {results['target']}")
    print(f"Mode: {results['mode']}")
    print(f"Success: {results['success']}")
    print(f"Duration: {results.get('duration', 0):.2f} seconds")
    print(f"Vulnerabilities: {len(results.get('vulnerabilities', []))}")
    print(f"Exploits: {len(results.get('exploits', []))}")

async def example_custom_attacks():
    """Example of custom attack modes"""
    print("\n CUSTOM ATTACKS EXAMPLE")
    print("=" * 50)
    
    logger = Logger()
    engine = AresEngine()
    engine.initialize()
    
    target = "https://example.com"
    
    # SQLMap-style attack
    print(" SQLMap-Style Attack:")
    config = ScanConfig(
        target_url=target,
        scan_types=[ScanType.SQL_INJECTION],
        threads=50,
        timeout=30
    )
    results = engine.run_scan(config)
    print(f"SQL Injection scan completed: {len(results.get('results', {}))} results")
    
    # Burp Suite-style attack
    print("\n Burp Suite-Style Attack:")
    config = ScanConfig(
        target_url=target,
        scan_types=[ScanType.COMPREHENSIVE],
        threads=30,
        timeout=30
    )
    results = engine.run_scan(config)
    print(f"Comprehensive scan completed: {len(results.get('results', {}))} results")

def example_hacker_interface():
    """Example of hacker interface features"""
    print("\n HACKER INTERFACE EXAMPLE")
    print("=" * 50)
    
    from aresprobe.cli.interface import AresCLI
    
    # Create CLI instance
    cli = AresCLI()
    
    # Demonstrate glitch effect
    print("Glitch effect example:")
    glitched = cli._glitch_text("ARESPROBE HACKER EDITION")
    print(f"Original: ARESPROBE HACKER EDITION")
    print(f"Glitched: {glitched}")
    
    # Demonstrate matrix effect
    print("\nMatrix effect example:")
    cli._matrix_effect()
    
    # Show system status
    print("\nSystem status:")
    cli._show_status()

def example_attack_modes():
    """Example of different attack modes"""
    print("\n ATTACK MODES EXAMPLE")
    print("=" * 50)
    
    logger = Logger()
    hacker_engine = HackerEngine(logger)
    
    # Stealth mode
    hacker_engine.set_attack_mode(AttackMode.STEALTH)
    status = hacker_engine.get_attack_status()
    print(f"Stealth mode: {status}")
    
    # Aggressive mode
    hacker_engine.set_attack_mode(AttackMode.AGGRESSIVE)
    status = hacker_engine.get_attack_status()
    print(f"Aggressive mode: {status}")
    
    # Nuclear mode
    hacker_engine.set_attack_mode(AttackMode.NUCLEAR)
    status = hacker_engine.get_attack_status()
    print(f"Nuclear mode: {status}")

def example_visualization():
    """Example of visualization features"""
    print("\n VISUALIZATION EXAMPLE")
    print("=" * 50)
    
    from aresprobe.cli.interface import AresCLI
    
    cli = AresCLI()
    
    # Show hacker banner
    print("Hacker banner:")
    cli._display_hacker_banner()
    
    # Show matrix mode
    print("\nMatrix mode:")
    cli._display_matrix_mode()
    
    # Show help
    print("\nHelp system:")
    cli._show_hacker_help()

async def main():
    """Main example function"""
    print(" ARESPROBE HACKER EDITION - USAGE EXAMPLES")
    print("=" * 60)
    
    # Run examples
    await example_ultimate_hack()
    await example_custom_attacks()
    example_hacker_interface()
    example_attack_modes()
    example_visualization()
    
    print("\n EXAMPLES COMPLETE!")
    print(" Run 'python demo_hacker.py' for the full experience")
    print(" Welcome to the Matrix!")

if __name__ == "__main__":
    asyncio.run(main())
