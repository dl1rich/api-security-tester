#!/usr/bin/env python3
"""Quick verification test for new vulnerability detectors."""

import sys
import os

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

def test_statistics_module():
    """Test statistics module functionality."""
    print("Testing statistics module...")
    
    try:
        from testing.statistics import TestStatistics, PentesterGuidance
        
        # Test TestStatistics
        stats = TestStatistics()
        stats.start_testing()
        stats.record_test_execution('/api/users', 'SQL_INJECTION', 1.5)
        stats.end_testing()
        
        avg_times = stats.get_average_time_per_endpoint()
        print(f"✓ TestStatistics works: {avg_times}")
        
        # Test PentesterGuidance
        guidance = PentesterGuidance.get_vulnerability_guidance('SQL_INJECTION')
        print(f"✓ PentesterGuidance works: {len(guidance['exploitation_steps'])} steps")
        
        return True
    except Exception as e:
        print(f"✗ Statistics test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    test_statistics_module()
