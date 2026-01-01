"""
environment.py - Runtime context bootstrapping
Creates canonical runtime_context.json with execution environment metadata
"""

import json
import os
import sys
import platform
import hashlib
from datetime import datetime
from pathlib import Path
import socket
import logging
from typing import Dict, Any

# Import existing runtime_db for path management
try:
    from runtime_db import RuntimePaths
except ImportError:
    # Fallback if runtime_db not available
    class RuntimePaths:
        BASE_DIR = Path(os.getenv("PROGRAMDATA", "C:\\ProgramData")) / "SmartPatch"
        DB_DIR = BASE_DIR / "runtime"
        
        @staticmethod
        def init_dirs():
            for d in [RuntimePaths.BASE_DIR, RuntimePaths.DB_DIR]:
                d.mkdir(parents=True, exist_ok=True)

logger = logging.getLogger(__name__)


class RuntimeContext:
    """
    Captures and persists the execution context of the scanner.
    This is written once per scan and read by all modules.
    """
    
    def __init__(self):
        self.context = {}
        self.context_file = None
        
    def detect_environment(self) -> Dict[str, Any]:
        """Collect comprehensive environment metadata"""
        env = {
            "timestamp": datetime.utcnow().isoformat(),
            "python": {
                "version": sys.version,
                "version_info": {
                    "major": sys.version_info.major,
                    "minor": sys.version_info.minor,
                    "micro": sys.version_info.micro
                },
                "implementation": platform.python_implementation(),
                "executable": sys.executable,
                "path": sys.path
            },
            "system": {
                "platform": platform.platform(),
                "system": platform.system(),
                "release": platform.release(),
                "version": platform.version(),
                "machine": platform.machine(),
                "processor": platform.processor()
            },
            "execution": {
                "argv": sys.argv,
                "exec_prefix": sys.exec_prefix,
                "byteorder": sys.byteorder,
                "maxsize": sys.maxsize
            },
            "environment": {
                "cwd": os.getcwd(),
                "user": os.environ.get("USERNAME", os.environ.get("USER", "unknown")),
                "computername": socket.gethostname() if hasattr(socket, 'gethostname') else "unknown",
                "programdata": os.environ.get("PROGRAMDATA", "C:\\ProgramData")
            }
        }
        
        # Add admin flag detection
        env["execution"]["is_elevated"] = self._check_admin_privileges()
        
        # Generate context hash for idempotency
        context_str = json.dumps(env, sort_keys=True)
        env["context_hash"] = hashlib.sha256(context_str.encode()).hexdigest()
        
        return env
    
    def _check_admin_privileges(self) -> bool:
        """Check if running with elevated privileges"""
        try:
            # Platform-specific admin checks
            if os.name == 'nt':  # Windows
                import ctypes
                return ctypes.windll.shell32.IsUserAnAdmin() != 0
            else:  # Unix/Linux/Mac
                return os.geteuid() == 0
        except Exception:
            return False
    
    def write_context_file(self, force: bool = False) -> Path:
        """
        Write runtime context to JSON file.
        Returns path to context file.
        """
        RuntimePaths.init_dirs()
        
        # Generate context file path
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.context_file = RuntimePaths.DB_DIR / f"runtime_context_{timestamp}.json"
        
        # Collect context
        self.context = self.detect_environment()
        
        # Write to file
        try:
            with open(self.context_file, 'w') as f:
                json.dump(self.context, f, indent=2, default=str)
            logger.info(f"Runtime context written to: {self.context_file}")
            return self.context_file
        except Exception as e:
            logger.error(f"Failed to write runtime context: {e}")
            raise
    
    def read_context_file(self, context_file: Path = None) -> Dict[str, Any]:
        """
        Read existing runtime context from file.
        If no file specified, find the latest one.
        """
        if context_file:
            target_file = context_file
        else:
            # Find latest context file
            context_files = list(RuntimePaths.DB_DIR.glob("runtime_context_*.json"))
            if not context_files:
                raise FileNotFoundError("No runtime context files found")
            target_file = max(context_files, key=lambda p: p.stat().st_mtime)
        
        try:
            with open(target_file, 'r') as f:
                self.context = json.load(f)
            logger.info(f"Runtime context loaded from: {target_file}")
            return self.context
        except Exception as e:
            logger.error(f"Failed to read runtime context: {e}")
            raise
    
    def get_context(self) -> Dict[str, Any]:
        """Get current runtime context"""
        if not self.context:
            self.context = self.detect_environment()
        return self.context
    
    def get_context_value(self, key: str, default: Any = None) -> Any:
        """Get specific value from runtime context using dot notation"""
        if not self.context:
            self.context = self.detect_environment()
        
        keys = key.split('.')
        value = self.context
        
        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default
        
        return value


def bootstrap_runtime_context() -> RuntimeContext:
    """
    High-level bootstrap function.
    Call this at the start of the scanner to initialize runtime context.
    """
    logger.info("Bootstrapping runtime context...")
    
    context = RuntimeContext()
    context.write_context_file()
    
    # Log key context info
    ctx = context.get_context()
    logger.info(f"Context hash: {ctx.get('context_hash', 'unknown')}")
    logger.info(f"Python version: {ctx['python']['version_info']['major']}.{ctx['python']['version_info']['minor']}.{ctx['python']['version_info']['micro']}")
    logger.info(f"Elevated privileges: {ctx['execution']['is_elevated']}")
    
    return context


if __name__ == "__main__":
    # Configure logging for standalone execution
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Bootstrap and display context
    ctx = bootstrap_runtime_context()
    print(json.dumps(ctx.get_context(), indent=2, default=str))