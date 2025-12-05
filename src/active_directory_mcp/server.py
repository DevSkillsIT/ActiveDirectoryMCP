"""
Main server implementation for Active Directory MCP.

This module implements the core MCP server for Active Directory integration, providing:
- Configuration loading and validation
- Logging setup
- LDAP connection management
- MCP tool registration and routing
- Signal handling for graceful shutdown
- Client identification and security (Multi-tenant support)

The server exposes a comprehensive set of tools for managing Active Directory resources including:
- User management (create, modify, delete, enable/disable, password reset)
- Group management (create, modify, delete, membership management)
- Computer management (create, modify, delete, enable/disable)
- Organizational Unit management (create, modify, delete, move)
- Security operations (audit, permissions analysis, policy compliance)
- Client identification (get_client_info for multi-tenant environments)

Skills IT Soluções em Tecnologia - Multi-tenant enhancements
"""

import logging
import json
import os
import sys
import signal
from typing import Optional, List, Annotated

from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.tools import Tool
from mcp.types import TextContent as Content
from pydantic import Field

from .config.loader import load_config, validate_config
from .core.logging import setup_logging
from .core.ldap_manager import LDAPManager
from .core.client_security import ClientSecurityManager, init_security_manager, get_security_manager
from .tools.user import UserTools
from .tools.group import GroupTools
from .tools.computer import ComputerTools
from .tools.organizational_unit import OrganizationalUnitTools
from .tools.security import SecurityTools


class ActiveDirectoryMCPServer:
    """Main server class for Active Directory MCP."""

    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize the server.

        Args:
            config_path: Path to configuration file
        """
        # Store config path for client security
        self.config_path = config_path

        # Load and validate configuration
        self.config = load_config(config_path)
        validate_config(self.config)

        # Setup logging
        self.logger = setup_logging(self.config.logging)

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

        # Initialize MCP server
        self.mcp = FastMCP("ActiveDirectoryMCP")
        self._tests_passed: Optional[bool] = None
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
            self.logger.info(f"Client security initialized: {self.security_manager.client_name}")
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
                if connection_info.get('search_test'):
                    self.logger.info("LDAP search test passed")
                else:
                    self.logger.warning("LDAP search test failed")
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
        """
        Register MCP tools with the server.

        Initializes and registers all available tools with the MCP server:
        - Client identification tool (get_client_info)
        - User management tools
        - Group management tools
        - Computer management tools
        - Organizational Unit tools
        - Security and audit tools

        Each tool is registered with appropriate descriptions and parameter
        validation using Pydantic models.
        """

        # =====================================================================
        # CLIENT IDENTIFICATION TOOL (Multi-tenant support)
        # =====================================================================

        @self.mcp.tool(description="Get client/tenant information for this AD instance. Use this to confirm which client's AD you are connected to before performing operations.")
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
            return [Content(type="text", text=json.dumps(info, indent=2, ensure_ascii=False))]

        # =====================================================================
        # USER MANAGEMENT TOOLS
        # =====================================================================

        @self.mcp.tool(description="List users in Active Directory with optional filtering")
        def list_users(
            ou: Annotated[Optional[str], Field(description="Organizational Unit DN to search in", default=None)] = None,
            filter_criteria: Annotated[Optional[str], Field(description="Additional LDAP filter criteria", default=None)] = None,
            attributes: Annotated[Optional[List[str]], Field(description="Specific attributes to retrieve", default=None)] = None
        ):
            return self.user_tools.list_users(ou, filter_criteria, attributes)

        @self.mcp.tool(description="Get detailed information about a specific user")
        def get_user(
            username: Annotated[str, Field(description="Username (sAMAccountName) to search for")],
            attributes: Annotated[Optional[List[str]], Field(description="Specific attributes to retrieve", default=None)] = None
        ):
            return self.user_tools.get_user(username, attributes)

        @self.mcp.tool(description="Create a new user in Active Directory. IMPORTANT: Confirm client with get_client_info first!")
        def create_user(
            username: Annotated[str, Field(description="Username (sAMAccountName)")],
            password: Annotated[str, Field(description="User password")],
            first_name: Annotated[str, Field(description="User's first name")],
            last_name: Annotated[str, Field(description="User's last name")],
            email: Annotated[Optional[str], Field(description="User's email address", default=None)] = None,
            ou: Annotated[Optional[str], Field(description="Organizational Unit DN to create user in", default=None)] = None,
            additional_attributes: Annotated[Optional[dict], Field(description="Additional attributes to set", default=None)] = None,
            automation_token: Annotated[Optional[str], Field(description="Automation token for unattended operations (skips confirmation)", default=None)] = None,
            client_confirmation: Annotated[Optional[str], Field(description="Client name confirmation for manual operations", default=None)] = None
        ):
            # Check write permission
            perm = self._check_write_permission("create_user", username, automation_token, client_confirmation)
            if not perm.get("permitted"):
                return [Content(type="text", text=json.dumps(perm, indent=2, ensure_ascii=False))]

            return self.user_tools.create_user(username, password, first_name, last_name, email, ou, additional_attributes)

        @self.mcp.tool(description="Modify user attributes. IMPORTANT: Confirm client with get_client_info first!")
        def modify_user(
            username: Annotated[str, Field(description="Username to modify")],
            attributes: Annotated[dict, Field(description="Dictionary of attributes to modify")],
            automation_token: Annotated[Optional[str], Field(description="Automation token for unattended operations", default=None)] = None,
            client_confirmation: Annotated[Optional[str], Field(description="Client name confirmation", default=None)] = None
        ):
            perm = self._check_write_permission("modify_user", username, automation_token, client_confirmation)
            if not perm.get("permitted"):
                return [Content(type="text", text=json.dumps(perm, indent=2, ensure_ascii=False))]

            return self.user_tools.modify_user(username, attributes)

        @self.mcp.tool(description="Delete a user from Active Directory. IMPORTANT: Confirm client with get_client_info first!")
        def delete_user(
            username: Annotated[str, Field(description="Username to delete")],
            automation_token: Annotated[Optional[str], Field(description="Automation token for unattended operations", default=None)] = None,
            client_confirmation: Annotated[Optional[str], Field(description="Client name confirmation", default=None)] = None
        ):
            perm = self._check_write_permission("delete_user", username, automation_token, client_confirmation)
            if not perm.get("permitted"):
                return [Content(type="text", text=json.dumps(perm, indent=2, ensure_ascii=False))]

            return self.user_tools.delete_user(username)

        @self.mcp.tool(description="Enable a user account. IMPORTANT: Confirm client with get_client_info first!")
        def enable_user(
            username: Annotated[str, Field(description="Username to enable")],
            automation_token: Annotated[Optional[str], Field(description="Automation token for unattended operations", default=None)] = None,
            client_confirmation: Annotated[Optional[str], Field(description="Client name confirmation", default=None)] = None
        ):
            perm = self._check_write_permission("enable_user", username, automation_token, client_confirmation)
            if not perm.get("permitted"):
                return [Content(type="text", text=json.dumps(perm, indent=2, ensure_ascii=False))]

            return self.user_tools.enable_user(username)

        @self.mcp.tool(description="Disable a user account. IMPORTANT: Confirm client with get_client_info first!")
        def disable_user(
            username: Annotated[str, Field(description="Username to disable")],
            automation_token: Annotated[Optional[str], Field(description="Automation token for unattended operations", default=None)] = None,
            client_confirmation: Annotated[Optional[str], Field(description="Client name confirmation", default=None)] = None
        ):
            perm = self._check_write_permission("disable_user", username, automation_token, client_confirmation)
            if not perm.get("permitted"):
                return [Content(type="text", text=json.dumps(perm, indent=2, ensure_ascii=False))]

            return self.user_tools.disable_user(username)

        @self.mcp.tool(description="Reset user password. IMPORTANT: Confirm client with get_client_info first!")
        def reset_user_password(
            username: Annotated[str, Field(description="Username to reset password for")],
            new_password: Annotated[Optional[str], Field(description="New password (auto-generated if not provided)", default=None)] = None,
            force_change: Annotated[bool, Field(description="Force user to change password at next logon", default=True)] = True,
            password_never_expires: Annotated[bool, Field(description="Set password to never expire", default=False)] = False,
            automation_token: Annotated[Optional[str], Field(description="Automation token for unattended operations", default=None)] = None,
            client_confirmation: Annotated[Optional[str], Field(description="Client name confirmation", default=None)] = None
        ):
            perm = self._check_write_permission("reset_user_password", username, automation_token, client_confirmation)
            if not perm.get("permitted"):
                return [Content(type="text", text=json.dumps(perm, indent=2, ensure_ascii=False))]

            return self.user_tools.reset_password(username, new_password, force_change, password_never_expires)

        @self.mcp.tool(description="Get groups that a user is member of")
        def get_user_groups(
            username: Annotated[str, Field(description="Username to get groups for")]
        ):
            return self.user_tools.get_user_groups(username)

        # =====================================================================
        # GROUP MANAGEMENT TOOLS
        # =====================================================================

        @self.mcp.tool(description="List groups in Active Directory with optional filtering")
        def list_groups(
            ou: Annotated[Optional[str], Field(description="Organizational Unit DN to search in", default=None)] = None,
            filter_criteria: Annotated[Optional[str], Field(description="Additional LDAP filter criteria", default=None)] = None,
            attributes: Annotated[Optional[List[str]], Field(description="Specific attributes to retrieve", default=None)] = None
        ):
            return self.group_tools.list_groups(ou, filter_criteria, attributes)

        @self.mcp.tool(description="Get detailed information about a specific group")
        def get_group(
            group_name: Annotated[str, Field(description="Group name (sAMAccountName) to search for")],
            attributes: Annotated[Optional[List[str]], Field(description="Specific attributes to retrieve", default=None)] = None
        ):
            return self.group_tools.get_group(group_name, attributes)

        @self.mcp.tool(description="Create a new group in Active Directory. IMPORTANT: Confirm client with get_client_info first!")
        def create_group(
            group_name: Annotated[str, Field(description="Group name (sAMAccountName)")],
            display_name: Annotated[Optional[str], Field(description="Display name for the group", default=None)] = None,
            description: Annotated[Optional[str], Field(description="Group description", default=None)] = None,
            ou: Annotated[Optional[str], Field(description="Organizational Unit DN to create group in", default=None)] = None,
            group_scope: Annotated[str, Field(description="Group scope (Global, DomainLocal, Universal)", default="Global")] = "Global",
            group_type: Annotated[str, Field(description="Group type (Security, Distribution)", default="Security")] = "Security",
            additional_attributes: Annotated[Optional[dict], Field(description="Additional attributes to set", default=None)] = None,
            automation_token: Annotated[Optional[str], Field(description="Automation token for unattended operations", default=None)] = None,
            client_confirmation: Annotated[Optional[str], Field(description="Client name confirmation", default=None)] = None
        ):
            perm = self._check_write_permission("create_group", group_name, automation_token, client_confirmation)
            if not perm.get("permitted"):
                return [Content(type="text", text=json.dumps(perm, indent=2, ensure_ascii=False))]

            return self.group_tools.create_group(group_name, display_name, description, ou, group_scope, group_type, additional_attributes)

        @self.mcp.tool(description="Modify group attributes. IMPORTANT: Confirm client with get_client_info first!")
        def modify_group(
            group_name: Annotated[str, Field(description="Group name to modify")],
            attributes: Annotated[dict, Field(description="Dictionary of attributes to modify")],
            automation_token: Annotated[Optional[str], Field(description="Automation token for unattended operations", default=None)] = None,
            client_confirmation: Annotated[Optional[str], Field(description="Client name confirmation", default=None)] = None
        ):
            perm = self._check_write_permission("modify_group", group_name, automation_token, client_confirmation)
            if not perm.get("permitted"):
                return [Content(type="text", text=json.dumps(perm, indent=2, ensure_ascii=False))]

            return self.group_tools.modify_group(group_name, attributes)

        @self.mcp.tool(description="Delete a group from Active Directory. IMPORTANT: Confirm client with get_client_info first!")
        def delete_group(
            group_name: Annotated[str, Field(description="Group name to delete")],
            automation_token: Annotated[Optional[str], Field(description="Automation token for unattended operations", default=None)] = None,
            client_confirmation: Annotated[Optional[str], Field(description="Client name confirmation", default=None)] = None
        ):
            perm = self._check_write_permission("delete_group", group_name, automation_token, client_confirmation)
            if not perm.get("permitted"):
                return [Content(type="text", text=json.dumps(perm, indent=2, ensure_ascii=False))]

            return self.group_tools.delete_group(group_name)

        @self.mcp.tool(description="Add a member to a group. IMPORTANT: Confirm client with get_client_info first!")
        def add_group_member(
            group_name: Annotated[str, Field(description="Group name to add member to")],
            member_dn: Annotated[str, Field(description="Distinguished name of member to add")],
            automation_token: Annotated[Optional[str], Field(description="Automation token for unattended operations", default=None)] = None,
            client_confirmation: Annotated[Optional[str], Field(description="Client name confirmation", default=None)] = None
        ):
            perm = self._check_write_permission("add_group_member", f"{group_name}:{member_dn}", automation_token, client_confirmation)
            if not perm.get("permitted"):
                return [Content(type="text", text=json.dumps(perm, indent=2, ensure_ascii=False))]

            return self.group_tools.add_member(group_name, member_dn)

        @self.mcp.tool(description="Remove a member from a group. IMPORTANT: Confirm client with get_client_info first!")
        def remove_group_member(
            group_name: Annotated[str, Field(description="Group name to remove member from")],
            member_dn: Annotated[str, Field(description="Distinguished name of member to remove")],
            automation_token: Annotated[Optional[str], Field(description="Automation token for unattended operations", default=None)] = None,
            client_confirmation: Annotated[Optional[str], Field(description="Client name confirmation", default=None)] = None
        ):
            perm = self._check_write_permission("remove_group_member", f"{group_name}:{member_dn}", automation_token, client_confirmation)
            if not perm.get("permitted"):
                return [Content(type="text", text=json.dumps(perm, indent=2, ensure_ascii=False))]

            return self.group_tools.remove_member(group_name, member_dn)

        @self.mcp.tool(description="Get members of a group")
        def get_group_members(
            group_name: Annotated[str, Field(description="Group name to get members for")],
            recursive: Annotated[bool, Field(description="Include members of nested groups", default=False)] = False
        ):
            return self.group_tools.get_members(group_name, recursive)

        # =====================================================================
        # COMPUTER MANAGEMENT TOOLS
        # =====================================================================

        @self.mcp.tool(description="List computer objects in Active Directory")
        def list_computers(
            ou: Annotated[Optional[str], Field(description="Organizational Unit DN to search in", default=None)] = None,
            filter_criteria: Annotated[Optional[str], Field(description="Additional LDAP filter criteria", default=None)] = None,
            attributes: Annotated[Optional[List[str]], Field(description="Specific attributes to retrieve", default=None)] = None
        ):
            return self.computer_tools.list_computers(ou, filter_criteria, attributes)

        @self.mcp.tool(description="Get detailed information about a specific computer")
        def get_computer(
            computer_name: Annotated[str, Field(description="Computer name (sAMAccountName) to search for")],
            attributes: Annotated[Optional[List[str]], Field(description="Specific attributes to retrieve", default=None)] = None
        ):
            return self.computer_tools.get_computer(computer_name, attributes)

        @self.mcp.tool(description="Create a new computer object in Active Directory. IMPORTANT: Confirm client with get_client_info first!")
        def create_computer(
            computer_name: Annotated[str, Field(description="Computer name (without $ suffix)")],
            description: Annotated[Optional[str], Field(description="Computer description", default=None)] = None,
            ou: Annotated[Optional[str], Field(description="Organizational Unit DN to create computer in", default=None)] = None,
            dns_hostname: Annotated[Optional[str], Field(description="DNS hostname", default=None)] = None,
            additional_attributes: Annotated[Optional[dict], Field(description="Additional attributes to set", default=None)] = None,
            automation_token: Annotated[Optional[str], Field(description="Automation token for unattended operations", default=None)] = None,
            client_confirmation: Annotated[Optional[str], Field(description="Client name confirmation", default=None)] = None
        ):
            perm = self._check_write_permission("create_computer", computer_name, automation_token, client_confirmation)
            if not perm.get("permitted"):
                return [Content(type="text", text=json.dumps(perm, indent=2, ensure_ascii=False))]

            return self.computer_tools.create_computer(computer_name, description, ou, dns_hostname, additional_attributes)

        @self.mcp.tool(description="Modify computer attributes. IMPORTANT: Confirm client with get_client_info first!")
        def modify_computer(
            computer_name: Annotated[str, Field(description="Computer name to modify")],
            attributes: Annotated[dict, Field(description="Dictionary of attributes to modify")],
            automation_token: Annotated[Optional[str], Field(description="Automation token for unattended operations", default=None)] = None,
            client_confirmation: Annotated[Optional[str], Field(description="Client name confirmation", default=None)] = None
        ):
            perm = self._check_write_permission("modify_computer", computer_name, automation_token, client_confirmation)
            if not perm.get("permitted"):
                return [Content(type="text", text=json.dumps(perm, indent=2, ensure_ascii=False))]

            return self.computer_tools.modify_computer(computer_name, attributes)

        @self.mcp.tool(description="Delete a computer from Active Directory. IMPORTANT: Confirm client with get_client_info first!")
        def delete_computer(
            computer_name: Annotated[str, Field(description="Computer name to delete")],
            automation_token: Annotated[Optional[str], Field(description="Automation token for unattended operations", default=None)] = None,
            client_confirmation: Annotated[Optional[str], Field(description="Client name confirmation", default=None)] = None
        ):
            perm = self._check_write_permission("delete_computer", computer_name, automation_token, client_confirmation)
            if not perm.get("permitted"):
                return [Content(type="text", text=json.dumps(perm, indent=2, ensure_ascii=False))]

            return self.computer_tools.delete_computer(computer_name)

        @self.mcp.tool(description="Enable a computer account. IMPORTANT: Confirm client with get_client_info first!")
        def enable_computer(
            computer_name: Annotated[str, Field(description="Computer name to enable")],
            automation_token: Annotated[Optional[str], Field(description="Automation token for unattended operations", default=None)] = None,
            client_confirmation: Annotated[Optional[str], Field(description="Client name confirmation", default=None)] = None
        ):
            perm = self._check_write_permission("enable_computer", computer_name, automation_token, client_confirmation)
            if not perm.get("permitted"):
                return [Content(type="text", text=json.dumps(perm, indent=2, ensure_ascii=False))]

            return self.computer_tools.enable_computer(computer_name)

        @self.mcp.tool(description="Disable a computer account. IMPORTANT: Confirm client with get_client_info first!")
        def disable_computer(
            computer_name: Annotated[str, Field(description="Computer name to disable")],
            automation_token: Annotated[Optional[str], Field(description="Automation token for unattended operations", default=None)] = None,
            client_confirmation: Annotated[Optional[str], Field(description="Client name confirmation", default=None)] = None
        ):
            perm = self._check_write_permission("disable_computer", computer_name, automation_token, client_confirmation)
            if not perm.get("permitted"):
                return [Content(type="text", text=json.dumps(perm, indent=2, ensure_ascii=False))]

            return self.computer_tools.disable_computer(computer_name)

        @self.mcp.tool(description="Reset computer account password. IMPORTANT: Confirm client with get_client_info first!")
        def reset_computer_password(
            computer_name: Annotated[str, Field(description="Computer name to reset password for")],
            automation_token: Annotated[Optional[str], Field(description="Automation token for unattended operations", default=None)] = None,
            client_confirmation: Annotated[Optional[str], Field(description="Client name confirmation", default=None)] = None
        ):
            perm = self._check_write_permission("reset_computer_password", computer_name, automation_token, client_confirmation)
            if not perm.get("permitted"):
                return [Content(type="text", text=json.dumps(perm, indent=2, ensure_ascii=False))]

            return self.computer_tools.reset_computer_password(computer_name)

        @self.mcp.tool(description="Get computers that haven't logged in for specified number of days")
        def get_stale_computers(
            days: Annotated[int, Field(description="Number of days to consider stale", default=90)] = 90
        ):
            return self.computer_tools.get_stale_computers(days)

        # =====================================================================
        # ORGANIZATIONAL UNIT TOOLS
        # =====================================================================

        @self.mcp.tool(description="List Organizational Units in Active Directory")
        def list_organizational_units(
            parent_ou: Annotated[Optional[str], Field(description="Parent OU DN to search in", default=None)] = None,
            filter_criteria: Annotated[Optional[str], Field(description="Additional LDAP filter criteria", default=None)] = None,
            attributes: Annotated[Optional[List[str]], Field(description="Specific attributes to retrieve", default=None)] = None,
            recursive: Annotated[bool, Field(description="Search recursively in sub-OUs", default=True)] = True
        ):
            return self.ou_tools.list_ous(parent_ou, filter_criteria, attributes, recursive)

        @self.mcp.tool(description="Get detailed information about a specific Organizational Unit")
        def get_organizational_unit(
            ou_dn: Annotated[str, Field(description="Distinguished name of the OU")],
            attributes: Annotated[Optional[List[str]], Field(description="Specific attributes to retrieve", default=None)] = None
        ):
            return self.ou_tools.get_ou(ou_dn, attributes)

        @self.mcp.tool(description="Create a new Organizational Unit. IMPORTANT: Confirm client with get_client_info first!")
        def create_organizational_unit(
            name: Annotated[str, Field(description="Name of the OU")],
            parent_ou: Annotated[Optional[str], Field(description="Parent OU DN", default=None)] = None,
            description: Annotated[Optional[str], Field(description="OU description", default=None)] = None,
            managed_by: Annotated[Optional[str], Field(description="DN of user/group managing this OU", default=None)] = None,
            additional_attributes: Annotated[Optional[dict], Field(description="Additional attributes to set", default=None)] = None,
            automation_token: Annotated[Optional[str], Field(description="Automation token for unattended operations", default=None)] = None,
            client_confirmation: Annotated[Optional[str], Field(description="Client name confirmation", default=None)] = None
        ):
            perm = self._check_write_permission("create_organizational_unit", name, automation_token, client_confirmation)
            if not perm.get("permitted"):
                return [Content(type="text", text=json.dumps(perm, indent=2, ensure_ascii=False))]

            return self.ou_tools.create_ou(name, parent_ou, description, managed_by, additional_attributes)

        @self.mcp.tool(description="Modify OU attributes. IMPORTANT: Confirm client with get_client_info first!")
        def modify_organizational_unit(
            ou_dn: Annotated[str, Field(description="OU distinguished name to modify")],
            attributes: Annotated[dict, Field(description="Dictionary of attributes to modify")],
            automation_token: Annotated[Optional[str], Field(description="Automation token for unattended operations", default=None)] = None,
            client_confirmation: Annotated[Optional[str], Field(description="Client name confirmation", default=None)] = None
        ):
            perm = self._check_write_permission("modify_organizational_unit", ou_dn, automation_token, client_confirmation)
            if not perm.get("permitted"):
                return [Content(type="text", text=json.dumps(perm, indent=2, ensure_ascii=False))]

            return self.ou_tools.modify_ou(ou_dn, attributes)

        @self.mcp.tool(description="Delete an Organizational Unit. IMPORTANT: Confirm client with get_client_info first!")
        def delete_organizational_unit(
            ou_dn: Annotated[str, Field(description="OU distinguished name to delete")],
            force: Annotated[bool, Field(description="Force deletion even if OU contains objects", default=False)] = False,
            automation_token: Annotated[Optional[str], Field(description="Automation token for unattended operations", default=None)] = None,
            client_confirmation: Annotated[Optional[str], Field(description="Client name confirmation", default=None)] = None
        ):
            perm = self._check_write_permission("delete_organizational_unit", ou_dn, automation_token, client_confirmation)
            if not perm.get("permitted"):
                return [Content(type="text", text=json.dumps(perm, indent=2, ensure_ascii=False))]

            return self.ou_tools.delete_ou(ou_dn, force)

        @self.mcp.tool(description="Move an OU to a new parent. IMPORTANT: Confirm client with get_client_info first!")
        def move_organizational_unit(
            ou_dn: Annotated[str, Field(description="OU distinguished name to move")],
            new_parent_dn: Annotated[str, Field(description="New parent OU distinguished name")],
            automation_token: Annotated[Optional[str], Field(description="Automation token for unattended operations", default=None)] = None,
            client_confirmation: Annotated[Optional[str], Field(description="Client name confirmation", default=None)] = None
        ):
            perm = self._check_write_permission("move_organizational_unit", ou_dn, automation_token, client_confirmation)
            if not perm.get("permitted"):
                return [Content(type="text", text=json.dumps(perm, indent=2, ensure_ascii=False))]

            return self.ou_tools.move_ou(ou_dn, new_parent_dn)

        @self.mcp.tool(description="Get contents of an OU (users, groups, computers, sub-OUs)")
        def get_organizational_unit_contents(
            ou_dn: Annotated[str, Field(description="OU distinguished name")],
            object_types: Annotated[Optional[List[str]], Field(description="Types of objects to include", default=None)] = None
        ):
            return self.ou_tools.get_ou_contents(ou_dn, object_types)

        # =====================================================================
        # SECURITY AND AUDIT TOOLS
        # =====================================================================

        @self.mcp.tool(description="Get domain information and security settings")
        def get_domain_info():
            return self.security_tools.get_domain_info()

        @self.mcp.tool(description="Get information about privileged groups in the domain")
        def get_privileged_groups():
            return self.security_tools.get_privileged_groups()

        @self.mcp.tool(description="Get effective permissions for a user by analyzing group memberships")
        def get_user_permissions(
            username: Annotated[str, Field(description="Username to analyze permissions for")]
        ):
            return self.security_tools.get_user_permissions(username)

        @self.mcp.tool(description="Get users who haven't logged in for specified number of days")
        def get_inactive_users(
            days: Annotated[int, Field(description="Number of days to consider inactive", default=90)] = 90,
            include_disabled: Annotated[bool, Field(description="Include disabled accounts in results", default=False)] = False
        ):
            return self.security_tools.get_inactive_users(days, include_disabled)

        @self.mcp.tool(description="Get users with password policy violations")
        def get_password_policy_violations():
            return self.security_tools.get_password_policy_violations()

        @self.mcp.tool(description="Audit administrative accounts for security compliance")
        def audit_admin_accounts():
            return self.security_tools.audit_admin_accounts()

        # =====================================================================
        # SYSTEM TOOLS
        # =====================================================================

        @self.mcp.tool(description="Test LDAP connection and get server information")
        def test_connection():
            try:
                connection_info = self.ldap_manager.test_connection()
                return [Content(type="text", text=json.dumps(connection_info, indent=2))]
            except Exception as e:
                return [Content(type="text", text=json.dumps({
                    "success": False,
                    "error": str(e)
                }, indent=2))]

        @self.mcp.tool(description="Health check for Active Directory MCP server")
        def health():
            status = "ok" if self._tests_passed is True else ("degraded" if self._tests_passed is False else "unknown")
            health_info = {
                "status": status,
                "server": "ActiveDirectoryMCP",
                "tests_passed": self._tests_passed,
                "ldap_connection": "unknown"
            }

            # Add client info if available
            if self.security_manager:
                health_info["client"] = {
                    "name": self.security_manager.client_name,
                    "slug": self.security_manager.client_slug,
                    "domain": self.security_manager.domain
                }

            # Test LDAP connection
            try:
                connection_info = self.ldap_manager.test_connection()
                health_info["ldap_connection"] = "connected" if connection_info.get('connected') else "disconnected"
                health_info["ldap_server"] = connection_info.get('server', 'unknown')
            except Exception as e:
                health_info["ldap_connection"] = "error"
                health_info["ldap_error"] = str(e)

            return [Content(type="text", text=json.dumps(health_info, indent=2))]

        @self.mcp.tool(description="Get schema information for all available tools")
        def get_schema_info():
            schema_info = {
                "server": "ActiveDirectoryMCP",
                "version": "0.2.0",  # Updated version with multi-tenant support
                "multi_tenant": True,
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

            return [Content(type="text", text=json.dumps(schema_info, indent=2, ensure_ascii=False))]

    def start(self) -> None:
        """
        Start the MCP server.

        Initializes the server with:
        - Signal handlers for graceful shutdown (SIGINT, SIGTERM)
        - Async runtime for handling concurrent requests
        - Error handling and logging

        The server runs until terminated by a signal or fatal error.
        """
        import anyio

        def signal_handler(signum, frame):
            self.logger.info("Received signal to shutdown...")
            self.ldap_manager.disconnect()
            sys.exit(0)

        # Set up signal handlers
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)

        try:
            # Optionally run tests before serving
            run_tests = os.getenv("RUN_TESTS_ON_START", "0").lower() in ("1", "true", "yes", "on")
            if run_tests:
                import subprocess
                self.logger.info("Running startup tests (pytest)...")
                env = os.environ.copy()
                # Ensure src on PYTHONPATH for tests
                env["PYTHONPATH"] = f"{os.getcwd()}/src" + (":" + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")
                result = subprocess.run([sys.executable, "-m", "pytest", "-q"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=env)
                self._tests_passed = (result.returncode == 0)
                if not self._tests_passed:
                    self.logger.error("Startup tests failed. Health will be 'degraded'. Output:\n" + result.stdout.decode())
                else:
                    self.logger.info("Startup tests passed.")

            self.logger.info("Starting Active Directory MCP server...")
            self.logger.info(f"Connected to: {self.config.active_directory.server}")
            self.logger.info(f"Domain: {self.config.active_directory.domain}")

            # Log client info if available
            if self.security_manager:
                self.logger.info(f"Client: {self.security_manager.client_name} ({self.security_manager.client_slug})")

            anyio.run(self.mcp.run_stdio_async)

        except Exception as e:
            self.logger.error(f"Server error: {e}")
            self.ldap_manager.disconnect()
            sys.exit(1)


def main():
    """Main entry point for the server."""
    config_path = os.getenv("AD_MCP_CONFIG")
    if not config_path:
        print("AD_MCP_CONFIG environment variable must be set")
        sys.exit(1)

    try:
        server = ActiveDirectoryMCPServer(config_path)
        server.start()
    except KeyboardInterrupt:
        print("\nShutting down gracefully...")
        sys.exit(0)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
