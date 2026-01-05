#!/usr/bin/env python3
"""
Command Executor Module for HBAI-MON v3
Uses cn script with base64 encoding for bulletproof command execution
"""

import subprocess
import time
import base64
import re
import configparser
from typing import Dict


class CommandExecutor:
    """Execute commands via cn script with base64 encoding"""
    
    def __init__(self, ssh_config: dict, audit_logger, credentials_file: str = None):
        self.jumpserver = ssh_config.get('jumpserver', 'hbcsrv14')
        self.jumpserver_user = ssh_config.get('jumpserver_user', 'master')
        self.cn_script = 'cn'
        self.timeout = int(ssh_config.get('timeout', 120))
        self.audit = audit_logger
        
        # Load credentials for MySQL command expansion
        self.credentials = None
        if credentials_file:
            self.credentials = configparser.ConfigParser()
            self.credentials.read(credentials_file)
    
    def _expand_mysql_command(self, command: str, hostname: str) -> str:
        """Expand MySQL commands with credentials if available"""
        
        if not self.credentials:
            self.audit.log('WARNING', 'No credentials available for MySQL expansion')
            return command
        
        # Check if this is a MySQL command that needs credentials
        mysql_patterns = [
            (r'^mysql\s+', 'mysql'),
            (r'^mysqladmin\s+', 'mysqladmin'),
            (r'^mysqldump\s+', 'mysqldump'),
        ]
        
        cmd_type = None
        for pattern, cmd_name in mysql_patterns:
            if re.match(pattern, command):
                cmd_type = cmd_name
                break
        
        if not cmd_type:
            # Not a MySQL command
            return command
        
        self.audit.log('DEBUG', f'Detected MySQL command type: {cmd_type}')
        
        # Check various password patterns
        # Pattern 1: -p'password' or -p"password" or -ppassword (placeholder)
        has_placeholder = re.search(r"-p['\"]?password['\"]?", command, re.IGNORECASE)
        
        # Pattern 2: -p followed by space then non-password argument (interactive mode)
        # This catches: -p status, -p -e, -p --verbose, etc.
        has_interactive = re.search(r'-p\s+[^\'"\s]', command) and not re.search(r'-p\S', command)
        
        # Pattern 3: -p at end of command
        has_p_at_end = re.search(r'-p\s*$', command)
        
        # Pattern 4: -p with nothing attached (standalone -p followed by space or end)
        has_standalone_p = re.search(r'-p(?=\s|$)', command) and not re.search(r'-p\S', command)
        
        self.audit.log('DEBUG', f'Password detection: placeholder={has_placeholder}, interactive={has_interactive}, at_end={has_p_at_end}, standalone={has_standalone_p}')
        
        # Check if it already has a REAL password (not a placeholder)
        # Real password: -pSOMETHING where SOMETHING is not 'password' and not whitespace
        has_real_password = re.search(r'-p[^\s\'"]\S*', command) and not has_placeholder
        
        if has_real_password:
            self.audit.log('DEBUG', 'MySQL command already has real inline password')
            return command
        
        needs_expansion = has_placeholder or has_interactive or has_p_at_end or has_standalone_p
        
        if not needs_expansion:
            self.audit.log('DEBUG', 'MySQL command does not need password expansion')
            return command
        
        self.audit.log('DEBUG', f'MySQL command needs credential expansion: {command[:50]}')
        
        # Determine which credentials to use based on hostname
        cred_section = None
        if 'hbcsrv12' in hostname:
            if 'mysql_root' in self.credentials:
                cred_section = 'mysql_root'
                self.audit.log('DEBUG', f'Using credentials from [mysql_root] for {hostname}')
        
        if not cred_section:
            self.audit.log('WARNING', f'No MySQL credentials found for hostname: {hostname}')
            return command
        
        # Get credentials
        user = self.credentials[cred_section].get('user', 'root')
        password = self.credentials[cred_section].get('password', '')
        
        if not password:
            self.audit.log('ERROR', f'Password is empty in [{cred_section}]')
            return command
        
        self.audit.log('DEBUG', f'Found credentials - user: {user}, password length: {len(password)}')
        
        # Remove ALL password-related flags and placeholders
        cleaned = command
        # Remove -p'password', -p"password", -ppassword
        cleaned = re.sub(r"-p['\"]?password['\"]?", '', cleaned, flags=re.IGNORECASE)
        # Remove standalone -p (followed by space or end)
        cleaned = re.sub(r'-p(?=\s|$)', '', cleaned)
        # Remove any -pXXX that might remain
        cleaned = re.sub(r'-p\S+', '', cleaned)
        
        # Remove existing -u flag (we'll add it back)
        cleaned = re.sub(r'-u\s+\S+\s*', '', cleaned)
        
        # Clean up extra spaces
        cleaned = re.sub(r'\s+', ' ', cleaned).strip()
        
        self.audit.log('DEBUG', f'Cleaned command: {cleaned}')
        
        # Build new command: mysql -u USER -pPASSWORD <rest>
        # Insert credentials right after command name
        expanded = re.sub(
            f'^{cmd_type}\\s*',
            f'{cmd_type} -u {user} -p{password} ',
            cleaned
        )
        
        # Clean up any double spaces
        expanded = re.sub(r'\s+', ' ', expanded).strip()
        
        self.audit.log('INFO', f'MySQL command expanded successfully')
        self.audit.log('DEBUG', f'Original: {command[:80]}')
        self.audit.log('DEBUG', f'Expanded: {cmd_type} -u {user} -p*** ...')
        
        return expanded

    def execute_single_diagnostic(self, hostname: str, command: str) -> Dict:
        """Execute a single diagnostic command on target host via cn script"""
        
        start_time = time.time()
        result = {
            'command': command,
            'hostname': hostname,
            'success': False,
            'stdout': '',
            'stderr': '',
            'exit_code': -1,
            'execution_time': 0,
            'error_message': None
        }
        
        try:
            # Extract hostname without domain
            target_host = hostname.split('.')[0] if '.' in hostname else hostname
            
            # Expand MySQL commands with credentials if needed
            expanded_command = self._expand_mysql_command(command, hostname)
            
            if expanded_command != command:
                self.audit.log('DEBUG', f'Original command: {command}')
                self.audit.log('DEBUG', f'Expanded to: {expanded_command}')
            
            self.audit.log('DEBUG', f'Executing on {target_host}: {expanded_command[:200]}')
            
            # Encode command as base64 to avoid ALL quoting issues
            encoded_command = base64.b64encode(expanded_command.encode('utf-8')).decode('ascii')
            
            # DEBUG: Log what we're actually sending
            self.audit.log('DEBUG', f'Base64 encoded command: {encoded_command}')
            self.audit.log('DEBUG', f'Decoded back (verification): {base64.b64decode(encoded_command).decode("utf-8")}')
            
            # Build SSH command using cn script with --b64 flag
            ssh_cmd = [
                'ssh',
                '-o', 'LogLevel=ERROR',
                f'{self.jumpserver_user}@{self.jumpserver}',
                self.cn_script,
                '--b64',
                target_host,
                encoded_command
            ]
        
            # Execute
            proc = subprocess.run(
                ssh_cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout
            )
            
            result['exit_code'] = proc.returncode
            result['stdout'] = proc.stdout.strip()
            result['stderr'] = proc.stderr.strip()
            
            # Command is successful if exit code is 0
            result['success'] = (proc.returncode == 0)
            
            if result['success']:
                self.audit.log('INFO', f'Command successful on {target_host}')
            else:
                result['error_message'] = f"Exit code: {proc.returncode}"
                if result['stderr']:
                    result['error_message'] += f", stderr: {result['stderr'][:200]}"
                self.audit.log('WARNING', f'Command failed on {target_host}: {result["error_message"]}')
            
        except subprocess.TimeoutExpired:
            result['error_message'] = f"Command timed out after {self.timeout} seconds"
            self.audit.log('ERROR', f'Command timeout on {target_host}')
        except Exception as e:
            result['error_message'] = str(e)
            self.audit.log('ERROR', f'Command failed: {e}')
        finally:
            result['execution_time'] = round(time.time() - start_time, 2)
        
        return result
    
    def test_connectivity(self, hostname: str) -> bool:
        """Test if host is reachable via cn script"""
        result = self.execute_single_diagnostic(hostname, "echo 'connectivity_test'")
        return result['success'] and 'connectivity_test' in result['stdout']
