"""
HTTP-based MCP server implementation for Active Directory MCP.

This module provides an HTTP transport layer for the MCP server,
supporting both regular HTTP and streamable HTTP transports.

Includes multi-tenant security features:
- Client identification (get_client_info tool)
- Automation token support for unattended operations
- Write operation confirmation for manual operations

Skills IT Soluções em Tecnologia - Multi-tenant enhancements
"""

import logging
import json
import os
import sys
import signal
from typing import Optional
from datetime import datetime

try:
    from fastmcp import FastMCP
    FASTMCP_AVAILABLE = True
except ImportError:
    try:
        from mcp.server.fastmcp import FastMCP
        FASTMCP_AVAILABLE = True
    except ImportError:
        FASTMCP_AVAILABLE = False

from .config.loader import load_config, validate_config
from .core.logging import setup_logging
from .core.ldap_manager import LDAPManager
from .core.client_security import ClientSecurityManager, init_security_manager, get_security_manager
from .core.client_registry import get_client_registry, list_configured_clients as registry_list_clients
from .tools.user import UserTools
from .tools.group import GroupTools
from .tools.computer import ComputerTools
from .tools.organizational_unit import OrganizationalUnitTools
from .tools.security import SecurityTools


logger = logging.getLogger("active-directory-mcp.http")


class ActiveDirectoryMCPHTTPServer:
    """
    HTTP-based MCP server for Active Directory management.

    This server supports:
    - HTTP transport via FastMCP
    - All Active Directory management operations
    - Health checks and monitoring
    - Multi-tenant client identification
    - Automation token for unattended operations
    """

    def __init__(self,
                 config_path: Optional[str] = None,
                 host: str = "0.0.0.0",
                 port: int = 8813,
                 path: str = "/activedirectory-mcp"):
        """
        Initialize the HTTP MCP server.

        Args:
            config_path: Path to configuration file
            host: Server host address
            port: Server port
            path: HTTP path for MCP endpoint
        """
        if not FASTMCP_AVAILABLE:
            raise RuntimeError("FastMCP is not available. Please install fastmcp package.")

        # Store config path for client security
        self.config_path = config_path

        # Load and validate configuration
        self.config = load_config(config_path)
        validate_config(self.config)

        # Setup logging
        self.logger = setup_logging(self.config.logging)

        self.host = host
        self.port = port
        self.path = path

        # Initialize client security manager (for multi-tenant support)
        self._init_client_security()

        # Initialize LDAP manager
        self.ldap_manager = LDAPManager(
            self.config.active_directory,
            self.config.security,
            self.config.performance
        )

        # Test connection on startup
        self._test_initial_connection()

        # Initialize tools
        self.user_tools = UserTools(self.ldap_manager)
        self.group_tools = GroupTools(self.ldap_manager)
        self.computer_tools = ComputerTools(self.ldap_manager)
        self.ou_tools = OrganizationalUnitTools(self.ldap_manager)
        self.security_tools = SecurityTools(self.ldap_manager)

        # Initialize FastMCP
        self.mcp = FastMCP("ActiveDirectoryMCP-HTTP")

        # Setup tools
        self._setup_tools()

    def _init_client_security(self) -> None:
        """Initialize client security manager for multi-tenant support."""
        try:
            # Load raw config as dict for security manager
            if self.config_path and os.path.exists(self.config_path):
                with open(self.config_path, 'r') as f:
                    config_dict = json.load(f)
            else:
                config_dict = {}

            self.security_manager = init_security_manager(config_dict, self.config_path)
            self.logger.info(f"Client security initialized: {self.security_manager.client_name} ({self.security_manager.client_slug})")
        except Exception as e:
            self.logger.warning(f"Could not initialize client security: {e}")
            self.security_manager = None

    def _test_initial_connection(self) -> None:
        """Test initial LDAP connection."""
        try:
            self.logger.info("Testing initial LDAP connection...")
            connection_info = self.ldap_manager.test_connection()

            if connection_info.get('connected'):
                self.logger.info(f"Successfully connected to {connection_info.get('server')}:{connection_info.get('port')}")
            else:
                self.logger.error(f"Initial connection failed: {connection_info.get('error')}")

        except Exception as e:
            self.logger.error(f"Connection test error: {e}")

    def _check_write_permission(
        self,
        operation: str,
        target: str,
        automation_token: Optional[str] = None,
        client_confirmation: Optional[str] = None
    ) -> dict:
        """
        Check if write operation is permitted.

        Returns dict with 'permitted' boolean and 'message'.
        """
        if not self.security_manager:
            return {"permitted": True, "mode": "no_security", "message": "Security manager not initialized"}

        return self.security_manager.check_write_permission(
            operation, target, automation_token, client_confirmation
        )

    def _setup_tools(self) -> None:
        """Register MCP tools with appropriate descriptions."""

        # =====================================================================
        # CLIENT IDENTIFICATION TOOL (Multi-tenant support)
        # =====================================================================

        @self.mcp.tool(description="Get client/tenant information for this AD instance. ALWAYS call this first to confirm which client's AD you are connected to.")
        def get_client_info():
            """
            Returns information about the client/tenant this MCP instance is connected to.

            IMPORTANT: Always call this tool before performing write operations to confirm
            you are operating on the correct client's Active Directory.
            """
            if self.security_manager:
                info = self.security_manager.get_client_info()
            else:
                info = {
                    "client": {
                        "name": "Unknown",
                        "slug": "unknown",
                        "type": "unknown"
                    },
                    "domain": {
                        "name": self.config.active_directory.domain,
                        "base_dn": self.config.active_directory.base_dn
                    },
                    "warning": "⚠️ Security manager not initialized - client identification unavailable"
                }
            return self._format_response(info, "get_client_info")

        @self.mcp.tool(description="List all configured AD clients. Use this to check which clients have AD configured before trying to access an AD.")
        def list_ad_clients():
            """
            Lists all Active Directory clients configured in the MCP server.

            IMPORTANT: Before trying to access a client's AD, call this tool to verify
            the client has an AD instance configured. If the client is not in the list,
            you CANNOT access their AD - inform the user that no AD is configured for that client.

            Returns:
                - total: Number of configured clients
                - clients: List of clients with name, slug, domain and port
                - message: Formatted list for display
            """
            try:
                result = registry_list_clients()

                # Add current instance info
                if self.security_manager:
                    result["current_instance"] = {
                        "name": self.security_manager.client_name,
                        "slug": self.security_manager.client_slug,
                        "domain": self.security_manager.domain
                    }

                return self._format_response(result, "list_ad_clients")
            except Exception as e:
                self.logger.error(f"Error listing configured clients: {e}")
                return self._format_response({
                    "error": str(e),
                    "message": "Erro ao listar clientes configurados"
                }, "list_ad_clients")

        @self.mcp.tool(description="Check if a specific client has AD configured. Use this before any AD operation to validate the client exists.")
        def check_client_exists(client_name: str):
            """
            Verifies if a specific client has an Active Directory instance configured.

            IMPORTANT: Call this tool BEFORE trying to use any AD tools for a client.
            If this returns false, DO NOT attempt to call other AD tools - inform the user
            that no AD is configured for that client.

            Args:
                client_name: Name or slug of the client to check (e.g., "Skills IT", "skills", "ramada")

            Returns:
                - exists: Boolean indicating if client has AD configured
                - client: Client info if exists
                - message: Human-readable message
            """
            try:
                registry = get_client_registry()
                client = registry.get_client(client_name)

                if client:
                    return self._format_response({
                        "exists": True,
                        "client": client,
                        "message": f"✅ Cliente '{client.get('name')}' tem AD configurado (slug: {client.get('slug')})"
                    }, "check_client_exists")
                else:
                    # List available clients for reference
                    available = registry.list_client_names()
                    return self._format_response({
                        "exists": False,
                        "searched_for": client_name,
                        "available_clients": available,
                        "message": f"❌ Cliente '{client_name}' NÃO tem AD configurado. Clientes disponíveis: {', '.join(available) if available else 'Nenhum'}"
                    }, "check_client_exists")
            except Exception as e:
                self.logger.error(f"Error checking client: {e}")
                return self._format_response({
                    "error": str(e),
                    "exists": False,
                    "message": f"Erro ao verificar cliente: {str(e)}"
                }, "check_client_exists")

        # =====================================================================
        # USER MANAGEMENT TOOLS
        # =====================================================================

        @self.mcp.tool(description="List users in Active Directory")
        def list_users(ou: Optional[str] = None, filter_criteria: Optional[str] = None, attributes: Optional[list] = None):
            return self.user_tools.list_users(ou, filter_criteria, attributes)

        @self.mcp.tool(description="Get detailed information about a specific user")
        def get_user(username: str, attributes: Optional[list] = None):
            return self.user_tools.get_user(username, attributes)

        @self.mcp.tool(description="Create a new user in Active Directory. IMPORTANT: Confirm client with get_client_info first!")
        def create_user(username: str, password: str, first_name: str, last_name: str,
                       email: Optional[str] = None, ou: Optional[str] = None,
                       additional_attributes: Optional[dict] = None,
                       automation_token: Optional[str] = None,
                       client_confirmation: Optional[str] = None):
            # Check write permission
            perm = self._check_write_permission("create_user", username, automation_token, client_confirmation)
            if not perm.get("permitted"):
                return self._format_response(perm, "create_user")
            return self.user_tools.create_user(username, password, first_name, last_name, email, ou, additional_attributes)

        @self.mcp.tool(description="Modify user attributes. IMPORTANT: Confirm client with get_client_info first!")
        def modify_user(username: str, attributes: dict,
                       automation_token: Optional[str] = None,
                       client_confirmation: Optional[str] = None):
            perm = self._check_write_permission("modify_user", username, automation_token, client_confirmation)
            if not perm.get("permitted"):
                return self._format_response(perm, "modify_user")
            return self.user_tools.modify_user(username, attributes)

        @self.mcp.tool(description="Delete a user from Active Directory. IMPORTANT: Confirm client with get_client_info first!")
        def delete_user(username: str,
                       automation_token: Optional[str] = None,
                       client_confirmation: Optional[str] = None):
            perm = self._check_write_permission("delete_user", username, automation_token, client_confirmation)
            if not perm.get("permitted"):
                return self._format_response(perm, "delete_user")
            return self.user_tools.delete_user(username)

        @self.mcp.tool(description="Enable a user account. IMPORTANT: Confirm client with get_client_info first!")
        def enable_user(username: str,
                       automation_token: Optional[str] = None,
                       client_confirmation: Optional[str] = None):
            perm = self._check_write_permission("enable_user", username, automation_token, client_confirmation)
            if not perm.get("permitted"):
                return self._format_response(perm, "enable_user")
            return self.user_tools.enable_user(username)

        @self.mcp.tool(description="Disable a user account. IMPORTANT: Confirm client with get_client_info first!")
        def disable_user(username: str,
                        automation_token: Optional[str] = None,
                        client_confirmation: Optional[str] = None):
            perm = self._check_write_permission("disable_user", username, automation_token, client_confirmation)
            if not perm.get("permitted"):
                return self._format_response(perm, "disable_user")
            return self.user_tools.disable_user(username)

        @self.mcp.tool(description="Reset user password. IMPORTANT: Confirm client with get_client_info first!")
        def reset_user_password(username: str, new_password: Optional[str] = None,
                               force_change: bool = True, password_never_expires: bool = False,
                               automation_token: Optional[str] = None,
                               client_confirmation: Optional[str] = None):
            perm = self._check_write_permission("reset_user_password", username, automation_token, client_confirmation)
            if not perm.get("permitted"):
                return self._format_response(perm, "reset_user_password")
            return self.user_tools.reset_password(username, new_password, force_change, password_never_expires)

        @self.mcp.tool(description="Get groups that a user is member of")
        def get_user_groups(username: str):
            return self.user_tools.get_user_groups(username)

        # =====================================================================
        # GROUP MANAGEMENT TOOLS
        # =====================================================================

        @self.mcp.tool(description="List groups in Active Directory")
        def list_groups(ou: Optional[str] = None, filter_criteria: Optional[str] = None, attributes: Optional[list] = None):
            return self.group_tools.list_groups(ou, filter_criteria, attributes)

        @self.mcp.tool(description="Get detailed information about a specific group")
        def get_group(group_name: str, attributes: Optional[list] = None):
            return self.group_tools.get_group(group_name, attributes)

        @self.mcp.tool(description="Create a new group in Active Directory. IMPORTANT: Confirm client with get_client_info first!")
        def create_group(group_name: str, display_name: Optional[str] = None, description: Optional[str] = None,
                        ou: Optional[str] = None, group_scope: str = "Global", group_type: str = "Security",
                        additional_attributes: Optional[dict] = None,
                        automation_token: Optional[str] = None,
                        client_confirmation: Optional[str] = None):
            perm = self._check_write_permission("create_group", group_name, automation_token, client_confirmation)
            if not perm.get("permitted"):
                return self._format_response(perm, "create_group")
            return self.group_tools.create_group(group_name, display_name, description, ou, group_scope, group_type, additional_attributes)

        @self.mcp.tool(description="Modify group attributes. IMPORTANT: Confirm client with get_client_info first!")
        def modify_group(group_name: str, attributes: dict,
                        automation_token: Optional[str] = None,
                        client_confirmation: Optional[str] = None):
            perm = self._check_write_permission("modify_group", group_name, automation_token, client_confirmation)
            if not perm.get("permitted"):
                return self._format_response(perm, "modify_group")
            return self.group_tools.modify_group(group_name, attributes)

        @self.mcp.tool(description="Delete a group from Active Directory. IMPORTANT: Confirm client with get_client_info first!")
        def delete_group(group_name: str,
                        automation_token: Optional[str] = None,
                        client_confirmation: Optional[str] = None):
            perm = self._check_write_permission("delete_group", group_name, automation_token, client_confirmation)
            if not perm.get("permitted"):
                return self._format_response(perm, "delete_group")
            return self.group_tools.delete_group(group_name)

        @self.mcp.tool(description="Add a member to a group. IMPORTANT: Confirm client with get_client_info first!")
        def add_group_member(group_name: str, member_dn: str,
                            automation_token: Optional[str] = None,
                            client_confirmation: Optional[str] = None):
            perm = self._check_write_permission("add_group_member", f"{group_name}:{member_dn}", automation_token, client_confirmation)
            if not perm.get("permitted"):
                return self._format_response(perm, "add_group_member")
            return self.group_tools.add_member(group_name, member_dn)

        @self.mcp.tool(description="Remove a member from a group. IMPORTANT: Confirm client with get_client_info first!")
        def remove_group_member(group_name: str, member_dn: str,
                               automation_token: Optional[str] = None,
                               client_confirmation: Optional[str] = None):
            perm = self._check_write_permission("remove_group_member", f"{group_name}:{member_dn}", automation_token, client_confirmation)
            if not perm.get("permitted"):
                return self._format_response(perm, "remove_group_member")
            return self.group_tools.remove_member(group_name, member_dn)

        @self.mcp.tool(description="Get members of a group")
        def get_group_members(group_name: str, recursive: bool = False):
            return self.group_tools.get_members(group_name, recursive)

        # =====================================================================
        # COMPUTER MANAGEMENT TOOLS
        # =====================================================================

        @self.mcp.tool(description="List computer objects in Active Directory")
        def list_computers(ou: Optional[str] = None, filter_criteria: Optional[str] = None, attributes: Optional[list] = None):
            return self.computer_tools.list_computers(ou, filter_criteria, attributes)

        @self.mcp.tool(description="Get detailed information about a specific computer")
        def get_computer(computer_name: str, attributes: Optional[list] = None):
            return self.computer_tools.get_computer(computer_name, attributes)

        @self.mcp.tool(description="Create a new computer object in Active Directory. IMPORTANT: Confirm client with get_client_info first!")
        def create_computer(computer_name: str, description: Optional[str] = None, ou: Optional[str] = None,
                           dns_hostname: Optional[str] = None, additional_attributes: Optional[dict] = None,
                           automation_token: Optional[str] = None,
                           client_confirmation: Optional[str] = None):
            perm = self._check_write_permission("create_computer", computer_name, automation_token, client_confirmation)
            if not perm.get("permitted"):
                return self._format_response(perm, "create_computer")
            return self.computer_tools.create_computer(computer_name, description, ou, dns_hostname, additional_attributes)

        @self.mcp.tool(description="Modify computer attributes. IMPORTANT: Confirm client with get_client_info first!")
        def modify_computer(computer_name: str, attributes: dict,
                           automation_token: Optional[str] = None,
                           client_confirmation: Optional[str] = None):
            perm = self._check_write_permission("modify_computer", computer_name, automation_token, client_confirmation)
            if not perm.get("permitted"):
                return self._format_response(perm, "modify_computer")
            return self.computer_tools.modify_computer(computer_name, attributes)

        @self.mcp.tool(description="Delete a computer from Active Directory. IMPORTANT: Confirm client with get_client_info first!")
        def delete_computer(computer_name: str,
                           automation_token: Optional[str] = None,
                           client_confirmation: Optional[str] = None):
            perm = self._check_write_permission("delete_computer", computer_name, automation_token, client_confirmation)
            if not perm.get("permitted"):
                return self._format_response(perm, "delete_computer")
            return self.computer_tools.delete_computer(computer_name)

        @self.mcp.tool(description="Enable a computer account. IMPORTANT: Confirm client with get_client_info first!")
        def enable_computer(computer_name: str,
                           automation_token: Optional[str] = None,
                           client_confirmation: Optional[str] = None):
            perm = self._check_write_permission("enable_computer", computer_name, automation_token, client_confirmation)
            if not perm.get("permitted"):
                return self._format_response(perm, "enable_computer")
            return self.computer_tools.enable_computer(computer_name)

        @self.mcp.tool(description="Disable a computer account. IMPORTANT: Confirm client with get_client_info first!")
        def disable_computer(computer_name: str,
                            automation_token: Optional[str] = None,
                            client_confirmation: Optional[str] = None):
            perm = self._check_write_permission("disable_computer", computer_name, automation_token, client_confirmation)
            if not perm.get("permitted"):
                return self._format_response(perm, "disable_computer")
            return self.computer_tools.disable_computer(computer_name)

        @self.mcp.tool(description="Reset computer account password. IMPORTANT: Confirm client with get_client_info first!")
        def reset_computer_password(computer_name: str,
                                   automation_token: Optional[str] = None,
                                   client_confirmation: Optional[str] = None):
            perm = self._check_write_permission("reset_computer_password", computer_name, automation_token, client_confirmation)
            if not perm.get("permitted"):
                return self._format_response(perm, "reset_computer_password")
            return self.computer_tools.reset_computer_password(computer_name)

        @self.mcp.tool(description="Get stale computers (not logged in for specified days)")
        def get_stale_computers(days: int = 90):
            return self.computer_tools.get_stale_computers(days)

        # =====================================================================
        # ORGANIZATIONAL UNIT TOOLS
        # =====================================================================

        @self.mcp.tool(description="List Organizational Units in Active Directory")
        def list_organizational_units(parent_ou: Optional[str] = None, filter_criteria: Optional[str] = None,
                                     attributes: Optional[list] = None, recursive: bool = True):
            return self.ou_tools.list_ous(parent_ou, filter_criteria, attributes, recursive)

        @self.mcp.tool(description="Get detailed information about a specific Organizational Unit")
        def get_organizational_unit(ou_dn: str, attributes: Optional[list] = None):
            return self.ou_tools.get_ou(ou_dn, attributes)

        @self.mcp.tool(description="Create a new Organizational Unit. IMPORTANT: Confirm client with get_client_info first!")
        def create_organizational_unit(name: str, parent_ou: Optional[str] = None, description: Optional[str] = None,
                                      managed_by: Optional[str] = None, additional_attributes: Optional[dict] = None,
                                      automation_token: Optional[str] = None,
                                      client_confirmation: Optional[str] = None):
            perm = self._check_write_permission("create_organizational_unit", name, automation_token, client_confirmation)
            if not perm.get("permitted"):
                return self._format_response(perm, "create_organizational_unit")
            return self.ou_tools.create_ou(name, parent_ou, description, managed_by, additional_attributes)

        @self.mcp.tool(description="Modify OU attributes. IMPORTANT: Confirm client with get_client_info first!")
        def modify_organizational_unit(ou_dn: str, attributes: dict,
                                      automation_token: Optional[str] = None,
                                      client_confirmation: Optional[str] = None):
            perm = self._check_write_permission("modify_organizational_unit", ou_dn, automation_token, client_confirmation)
            if not perm.get("permitted"):
                return self._format_response(perm, "modify_organizational_unit")
            return self.ou_tools.modify_ou(ou_dn, attributes)

        @self.mcp.tool(description="Delete an Organizational Unit. IMPORTANT: Confirm client with get_client_info first!")
        def delete_organizational_unit(ou_dn: str, force: bool = False,
                                      automation_token: Optional[str] = None,
                                      client_confirmation: Optional[str] = None):
            perm = self._check_write_permission("delete_organizational_unit", ou_dn, automation_token, client_confirmation)
            if not perm.get("permitted"):
                return self._format_response(perm, "delete_organizational_unit")
            return self.ou_tools.delete_ou(ou_dn, force)

        @self.mcp.tool(description="Move an OU to a new parent. IMPORTANT: Confirm client with get_client_info first!")
        def move_organizational_unit(ou_dn: str, new_parent_dn: str,
                                    automation_token: Optional[str] = None,
                                    client_confirmation: Optional[str] = None):
            perm = self._check_write_permission("move_organizational_unit", ou_dn, automation_token, client_confirmation)
            if not perm.get("permitted"):
                return self._format_response(perm, "move_organizational_unit")
            return self.ou_tools.move_ou(ou_dn, new_parent_dn)

        @self.mcp.tool(description="Get contents of an OU")
        def get_organizational_unit_contents(ou_dn: str, object_types: Optional[list] = None):
            return self.ou_tools.get_ou_contents(ou_dn, object_types)

        # =====================================================================
        # SECURITY AND AUDIT TOOLS
        # =====================================================================

        @self.mcp.tool(description="Get domain information and security settings")
        def get_domain_info():
            return self.security_tools.get_domain_info()

        @self.mcp.tool(description="Get information about privileged groups")
        def get_privileged_groups():
            return self.security_tools.get_privileged_groups()

        @self.mcp.tool(description="Get effective permissions for a user")
        def get_user_permissions(username: str):
            return self.security_tools.get_user_permissions(username)

        @self.mcp.tool(description="Get inactive users")
        def get_inactive_users(days: int = 90, include_disabled: bool = False):
            return self.security_tools.get_inactive_users(days, include_disabled)

        @self.mcp.tool(description="Get users with password policy violations")
        def get_password_policy_violations():
            return self.security_tools.get_password_policy_violations()

        @self.mcp.tool(description="Audit administrative accounts")
        def audit_admin_accounts():
            return self.security_tools.audit_admin_accounts()

        # =====================================================================
        # SYSTEM TOOLS
        # =====================================================================

        @self.mcp.tool(description="Test LDAP connection")
        def test_connection():
            try:
                connection_info = self.ldap_manager.test_connection()
                return self._format_response(connection_info, "test_connection")
            except Exception as e:
                return self._format_response({
                    "success": False,
                    "error": str(e)
                }, "test_connection")

        @self.mcp.tool(description="Health check for Active Directory MCP server")
        def health():
            """
            Perform a real health check of the MCP server and LDAP connection.

            This performs an actual LDAP search to verify the connection is working,
            not just checking if the socket appears open.

            Returns:
                - status: 'ok', 'degraded', or 'error'
                - ldap_connection: Real connection status based on actual LDAP operation
                - connection_stats: Detailed statistics about connection health
            """
            health_info = {
                "status": "ok",
                "server": "ActiveDirectoryMCP-HTTP",
                "version": "0.2.1",
                "timestamp": datetime.now().isoformat(),
                "ldap_connection": "unknown"
            }

            # Add client info if available
            if self.security_manager:
                health_info["client"] = {
                    "name": self.security_manager.client_name,
                    "slug": self.security_manager.client_slug,
                    "domain": self.security_manager.domain
                }

            # Test LDAP connection with REAL search operation
            try:
                connection_info = self.ldap_manager.test_connection()

                # Check if search test passed (not just socket open)
                if connection_info.get('search_test'):
                    health_info["ldap_connection"] = "connected"
                    health_info["ldap_verified"] = True
                elif connection_info.get('connected'):
                    health_info["ldap_connection"] = "connected_unverified"
                    health_info["ldap_verified"] = False
                    health_info["status"] = "degraded"
                    health_info["warning"] = "Connection open but search test failed"
                else:
                    health_info["ldap_connection"] = "disconnected"
                    health_info["status"] = "error"

                health_info["ldap_server"] = connection_info.get('server', 'unknown')

                # Add connection statistics
                try:
                    stats = self.ldap_manager.get_connection_stats()
                    health_info["connection_stats"] = {
                        "seconds_since_last_operation": round(stats.get('seconds_since_last_operation', 0), 1),
                        "connection_errors": stats.get('connection_errors', 0),
                        "keepalive_enabled": stats.get('keepalive_enabled', False),
                        "keepalive_thread_alive": stats.get('keepalive_thread_alive', False)
                    }
                except Exception:
                    pass

            except Exception as e:
                health_info["ldap_connection"] = "error"
                health_info["ldap_error"] = str(e)
                health_info["status"] = "error"

            return self._format_response(health_info, "health")

        @self.mcp.tool(description="Get schema information for all available tools")
        def get_schema_info():
            schema_info = {
                "server": "ActiveDirectoryMCP-HTTP",
                "version": "0.2.0",
                "multi_tenant": True,
                "endpoint": f"http://{self.host}:{self.port}{self.path}",
                "tools": {
                    "user_tools": self.user_tools.get_schema_info(),
                    "group_tools": self.group_tools.get_schema_info(),
                    "computer_tools": self.computer_tools.get_schema_info(),
                    "ou_tools": self.ou_tools.get_schema_info(),
                    "security_tools": self.security_tools.get_schema_info()
                }
            }

            # Add client info
            if self.security_manager:
                schema_info["client"] = self.security_manager.get_client_info()

            return self._format_response(schema_info, "get_schema_info")

    def _format_response(self, data, operation: str = "operation"):
        """Format response data for MCP."""
        from mcp.types import TextContent as Content

        try:
            if isinstance(data, (dict, list)):
                formatted_data = json.dumps(data, indent=2, ensure_ascii=False)
            else:
                formatted_data = str(data)

            return [Content(type="text", text=formatted_data)]

        except Exception as e:
            self.logger.error(f"Error formatting response for {operation}: {e}")
            error_response = {
                "error": f"Failed to format response: {str(e)}",
                "operation": operation
            }
            return [Content(type="text", text=json.dumps(error_response, indent=2))]

    def run(self) -> None:
        """
        Start the HTTP MCP server.

        Runs the server with HTTP transport on the configured
        host and port.
        """
        def signal_handler(signum, frame):
            self.logger.info("Received signal to shutdown HTTP server...")
            self.ldap_manager.disconnect()
            sys.exit(0)

        # Set up signal handlers
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)

        try:
            self.logger.info(f"Starting Active Directory MCP HTTP server on {self.host}:{self.port}{self.path}")
            self.logger.info(f"Connected to: {self.config.active_directory.server}")
            self.logger.info(f"Domain: {self.config.active_directory.domain}")

            # Log client info if available
            if self.security_manager:
                self.logger.info(f"Client: {self.security_manager.client_name} ({self.security_manager.client_slug})")

            # Run with FastMCP's built-in HTTP transport
            self.mcp.run(
                transport="http",
                host=self.host,
                port=self.port,
                path=self.path
            )
        except Exception as e:
            self.logger.error(f"HTTP server error: {e}")
            self.ldap_manager.disconnect()
            sys.exit(1)


class ActiveDirectoryMCPCommand:
    """
    Command runner for Active Directory MCP HTTP server.

    This class can be used as a standalone command runner.
    """

    help = "Active Directory MCP HTTP Server"

    def __init__(self):
        self.server = None

    def add_arguments(self, parser):
        """Add command line arguments."""
        parser.add_argument(
            '--host',
            type=str,
            default='0.0.0.0',
            help='Server host (default: 0.0.0.0)'
        )
        parser.add_argument(
            '--port',
            type=int,
            default=8813,
            help='Server port (default: 8813)'
        )
        parser.add_argument(
            '--path',
            type=str,
            default='/activedirectory-mcp',
            help='HTTP path (default: /activedirectory-mcp)'
        )
        parser.add_argument(
            '--config',
            type=str,
            help='Configuration file path'
        )

    def handle(self, *args, **options):
        """Handle the command execution."""
        config_path = options.get('config') or os.getenv('AD_MCP_CONFIG')

        self.server = ActiveDirectoryMCPHTTPServer(
            config_path=config_path,
            host=options.get('host', '0.0.0.0'),
            port=options.get('port', 8813),
            path=options.get('path', '/activedirectory-mcp')
        )

        self.server.run()


def main():
    """Main entry point for standalone execution."""
    import argparse

    parser = argparse.ArgumentParser(description='Active Directory MCP HTTP Server')
    command = ActiveDirectoryMCPCommand()
    command.add_arguments(parser)

    args = parser.parse_args()
    options = vars(args)

    try:
        command.handle(**options)
    except KeyboardInterrupt:
        print("\nShutting down gracefully...")
        sys.exit(0)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
