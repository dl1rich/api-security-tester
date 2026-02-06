"""Dependency injection for shared instances."""

# Singleton instances
_parser_instance = None
_test_manager_instance = None


def get_parser():
    """Get the shared OpenAPIParser instance."""
    global _parser_instance
    if _parser_instance is None:
        from parser.openapi_parser import OpenAPIParser
        _parser_instance = OpenAPIParser()
    return _parser_instance


def get_test_manager():
    """Get the shared TestManager instance."""
    global _test_manager_instance
    if _test_manager_instance is None:
        from testing.test_manager import TestManager
        _test_manager_instance = TestManager()
    return _test_manager_instance
