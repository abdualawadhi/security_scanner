"""
Professional Web Frontend for Low-Code Security Scanner

This module provides a modern web-based interface with:
- Real-time scan progress via WebSocket
- Interactive vulnerability management
- Professional dashboards and analytics
- Report generation and export
"""

from .app import create_app, socketio

__all__ = ['create_app', 'socketio']
