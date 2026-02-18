"""
MCP client for communicating with the ARM MCP server via JSON-RPC over stdio.

Spawns the ARM MCP container (Docker/Podman), sends tool calls, and parses responses.
Used to enrich Unknown/Needs Verification components with Arm Ecosystem Dashboard data.
"""

import json
import logging
import shutil
import subprocess
import threading
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

ARM_MCP_IMAGE = "armlimited/arm-mcp:latest"


class ArmMcpClient:
    """Communicates with the ARM MCP server container via JSON-RPC over stdio."""

    def __init__(self):
        self._process: Optional[subprocess.Popen] = None
        self._runtime: Optional[str] = None
        self._request_id = 0
        self._lock = threading.Lock()

    def _detect_runtime(self) -> Optional[str]:
        for rt in ("podman", "docker"):
            if shutil.which(rt):
                logger.debug(f"Found container runtime: {rt}")
                return rt
        return None

    def connect(self) -> bool:
        """Start the ARM MCP container and initialize the MCP session."""
        self._runtime = self._detect_runtime()
        if not self._runtime:
            logger.warning("No container runtime (docker/podman) found - ARM ecosystem lookup will be skipped")
            return False

        try:
            self._process = subprocess.Popen(
                [self._runtime, "run", "--rm", "-i", ARM_MCP_IMAGE],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
            )
            # Send MCP initialize
            resp = self._send_request("initialize", {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "graviton-validator", "version": "1.0.0"}
            })
            if resp and "result" in resp:
                # Send initialized notification
                self._send_notification("notifications/initialized", {})
                logger.info("ARM MCP server connected successfully")
                return True
            else:
                logger.warning(f"ARM MCP server initialization failed: {resp}")
                self.close()
                return False
        except Exception as e:
            logger.warning(f"Failed to start ARM MCP server: {e}")
            self.close()
            return False

    def knowledge_base_search(self, query: str) -> List[Dict]:
        """Search the ARM knowledge base. Returns list of results with url, title, snippet, distance."""
        if not self._process:
            return []
        resp = self._call_tool("knowledge_base_search", {"query": query})
        if resp and isinstance(resp, list):
            return resp
        return []

    def _call_tool(self, tool_name: str, arguments: Dict) -> Optional[any]:
        """Call an MCP tool and return parsed result."""
        resp = self._send_request("tools/call", {
            "name": tool_name,
            "arguments": arguments
        })
        if not resp or "result" not in resp:
            return None
        # MCP tool results are in result.content[].text
        content = resp["result"].get("content", [])
        for item in content:
            if item.get("type") == "text":
                try:
                    return json.loads(item["text"])
                except (json.JSONDecodeError, TypeError):
                    return item.get("text")
        return None

    def _send_request(self, method: str, params: Dict) -> Optional[Dict]:
        """Send a JSON-RPC request and read the response."""
        with self._lock:
            if not self._process or self._process.poll() is not None:
                return None
            self._request_id += 1
            msg = {"jsonrpc": "2.0", "id": self._request_id, "method": method, "params": params}
            try:
                line = json.dumps(msg) + "\n"
                self._process.stdin.write(line)
                self._process.stdin.flush()
                resp_line = self._process.stdout.readline()
                if resp_line:
                    return json.loads(resp_line.strip())
            except Exception as e:
                logger.debug(f"MCP request error: {e}")
            return None

    def _send_notification(self, method: str, params: Dict):
        """Send a JSON-RPC notification (no response expected)."""
        with self._lock:
            if not self._process or self._process.poll() is not None:
                return
            msg = {"jsonrpc": "2.0", "method": method, "params": params}
            try:
                self._process.stdin.write(json.dumps(msg) + "\n")
                self._process.stdin.flush()
            except Exception:
                pass

    def close(self):
        """Shut down the MCP server container."""
        if self._process:
            try:
                self._process.stdin.close()
                self._process.terminate()
                self._process.wait(timeout=5)
            except Exception:
                try:
                    self._process.kill()
                except Exception:
                    pass
            self._process = None
