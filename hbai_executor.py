#!/usr/bin/env python3
"""
Command Executor Module for HBAI-MON v3
Handles SSH connections through jumpserver with cn script
"""

import paramiko
import time
from typing import Dict, Optional


class CommandExecutor:
    """Execute commands via SSH through jumpserver"""
    
    def __init__(self, ssh_config: dict, audit_logger):
        self.jumpserver = ssh_config.get('jumpserver', 'jumpserver.internal')
        self.jumpserver_user = ssh_config.get('jumpserver_user', 'master')
        self.jumpserver_key = ssh_config.get('key_file', '/home/master/.ssh/id_rsa')
        self.timeout = int(ssh_config.get('timeout', 30))
        self.audit = audit_logger
    
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
            # Connect to jumpserver
            ssh_client = paramiko.SSHClient()
            ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            ssh_client.connect(
                hostname=self.jumpserver,
                username=self.jumpserver_user,
                key_filename=self.jumpserver_key,
                timeout=self.timeout
            )
            
            # Build the full command using cn script
            # cn script automatically handles getting root
            full_command = f"cn {hostname} '{command}'"
            
            # Execute command
            stdin, stdout, stderr = ssh_client.exec_command(
                full_command,
                timeout=self.timeout
            )
            
            # Get results
            result['stdout'] = stdout.read().decode('utf-8', errors='replace')
            result['stderr'] = stderr.read().decode('utf-8', errors='replace')
            result['exit_code'] = stdout.channel.recv_exit_status()
            result['success'] = (result['exit_code'] == 0)
            
        except paramiko.ssh_exception.SSHException as e:
            result['error_message'] = f"SSH error: {str(e)}"
            self.audit.log('ERROR', f'SSH error to {hostname}', {'error': str(e)})
        except paramiko.ssh_exception.NoValidConnectionsError:
            result['error_message'] = f"Cannot connect to jumpserver {self.jumpserver}"
            self.audit.log('ERROR', f'Cannot connect to jumpserver', 
                         {'jumpserver': self.jumpserver})
        except Exception as e:
            result['error_message'] = f"Unexpected error: {str(e)}"
            self.audit.log('ERROR', f'Unexpected error executing command', 
                         {'error': str(e), 'hostname': hostname})
        finally:
            if ssh_client:
                ssh_client.close()
            
            result['execution_time'] = round(time.time() - start_time, 2)
        
        return result
    
    def test_connectivity(self, hostname: str) -> bool:
        """Test if host is reachable via jumpserver"""
        result = self.execute_single_diagnostic(hostname, "echo 'test'")
        return result['success']
