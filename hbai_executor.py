#!/usr/bin/env python3
"""
Command Executor Module for HBAI-MON v3
Handles SSH connections through jumpserver with cn script
"""

import paramiko
import time
import socket
from typing import Dict, Optional


class CommandExecutor:
    """Execute commands via SSH through jumpserver"""
    
    def __init__(self, ssh_config: dict, audit_logger):
        self.jumpserver = ssh_config.get('jumpserver', 'hbcsrv14')  # Default to hbcsrv14
        self.jumpserver_user = ssh_config.get('jumpserver_user', 'master')
        self.jumpserver_key = ssh_config.get('key_file', '/home/master/.ssh/id_rsa')
        self.timeout = int(ssh_config.get('timeout', 30))
        self.audit = audit_logger
        
        # Log configuration for debugging
        self.audit.log('INFO', 'CommandExecutor initialized', {
            'jumpserver': self.jumpserver,
            'user': self.jumpserver_user,
            'key_file': self.jumpserver_key
        })
    
    def execute_single_diagnostic(self, hostname: str, command: str) -> Dict:
        """Execute a single diagnostic command on target host via jumpserver"""
        
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
        
        ssh_client = None
        try:
            # Connect to jumpserver (hbcsrv14)
            ssh_client = paramiko.SSHClient()
            ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            self.audit.log('INFO', f'Connecting to jumpserver {self.jumpserver} as {self.jumpserver_user}')
            
            # Connect using key authentication
            ssh_client.connect(
                hostname=self.jumpserver,
                username=self.jumpserver_user,
                key_filename=self.jumpserver_key,
                timeout=self.timeout,
                look_for_keys=True,
                allow_agent=True
            )
            
            self.audit.log('INFO', f'Connected to {self.jumpserver}, executing command on {hostname}')
            
            # Build the command: cn <target_host> '<command>'
            # The cn script on hbcsrv14 handles the connection to target host and gets root
            full_command = f"cn {hostname} '{command}'"
            
            # Log the full command for debugging
            self.audit.log('DEBUG', f'Executing: {full_command}')
            
            # Execute command on jumpserver, which will use cn to reach target
            stdin, stdout, stderr = ssh_client.exec_command(
                full_command,
                timeout=self.timeout
            )
            
            # Get results
            result['stdout'] = stdout.read().decode('utf-8', errors='replace')
            result['stderr'] = stderr.read().decode('utf-8', errors='replace')
            result['exit_code'] = stdout.channel.recv_exit_status()
            
            # Check for success (exit code 0 means success)
            result['success'] = (result['exit_code'] == 0)
            
            if result['success']:
                self.audit.log('INFO', f'Command successful on {hostname}')
            else:
                # Log any errors
                self.audit.log('WARNING', f'Command returned non-zero exit code on {hostname}', {
                    'exit_code': result['exit_code'],
                    'stderr': result['stderr'][:500] if result['stderr'] else 'No stderr output'
                })
            
        except paramiko.AuthenticationException as e:
            result['error_message'] = f"Authentication failed to {self.jumpserver}: {str(e)}"
            self.audit.log('ERROR', 'SSH authentication failed', {
                'error': str(e),
                'jumpserver': self.jumpserver,
                'user': self.jumpserver_user
            })
        except paramiko.SSHException as e:
            result['error_message'] = f"SSH connection error: {str(e)}"
            self.audit.log('ERROR', f'SSH error connecting to {self.jumpserver}', {'error': str(e)})
        except socket.timeout:
            result['error_message'] = f"Connection timeout to {self.jumpserver}"
            self.audit.log('ERROR', 'Connection timeout', {'jumpserver': self.jumpserver})
        except socket.error as e:
            result['error_message'] = f"Network error: {str(e)}"
            self.audit.log('ERROR', f'Network error connecting to {self.jumpserver}', {'error': str(e)})
        except FileNotFoundError:
            result['error_message'] = f"SSH key file not found: {self.jumpserver_key}"
            self.audit.log('ERROR', 'SSH key file not found', {'key_file': self.jumpserver_key})
        except Exception as e:
            result['error_message'] = f"Unexpected error: {str(e)}"
            self.audit.log('ERROR', 'Unexpected error', {
                'error': str(e),
                'error_type': type(e).__name__,
                'hostname': hostname,
                'jumpserver': self.jumpserver
            })
        finally:
            if ssh_client:
                ssh_client.close()
            
            result['execution_time'] = round(time.time() - start_time, 2)
        
        return result
    
    def test_connectivity(self, hostname: str) -> bool:
        """Test if host is reachable via jumpserver"""
        result = self.execute_single_diagnostic(hostname, "echo 'connectivity test'")
        return result['success']
