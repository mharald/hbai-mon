#!/usr/bin/env python3
"""
Command Executor Module for HBAI-MON v3
Simplified version using helper script on jumpserver
"""

import paramiko
import time
from typing import Dict, Optional


class CommandExecutor:
    """Execute commands via SSH through jumpserver"""
    
    def __init__(self, ssh_config: dict, audit_logger):
        self.jumpserver = ssh_config.get('jumpserver', 'hbcsrv14')
        self.jumpserver_user = ssh_config.get('jumpserver_user', 'master')
        self.jumpserver_key = ssh_config.get('key_file', '/root/.ssh/id_rsa')
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
            
            self.audit.log('DEBUG', f'Connecting to {self.jumpserver}')
            
            ssh_client.connect(
                hostname=self.jumpserver,
                username=self.jumpserver_user,
                key_filename=self.jumpserver_key,
                timeout=self.timeout,
                look_for_keys=True,
                allow_agent=True
            )
            
            # Extract hostname without domain
            target_host = hostname.split('.')[0] if '.' in hostname else hostname
            
            # Use the helper script
            exec_cmd = f"/usr/bin/hbai-remote-exec '{target_host}' '{command}'"
            
            self.audit.log('DEBUG', f'Executing on {target_host}: {command[:100]}')
            
            # Execute via helper script
            stdin, stdout, stderr = ssh_client.exec_command(exec_cmd, timeout=90)
            
            # Get output
            raw_output = stdout.read().decode('utf-8', errors='replace')
            stderr_output = stderr.read().decode('utf-8', errors='replace')
            exit_code = stdout.channel.recv_exit_status()
            
            # Clean output - remove cn script artifacts
            lines = raw_output.split('\n')
            cleaned = []
            skip_patterns = [
                'spawn cn', 'Extracted FQDN', 'Checking credentials',
                'Using default', 'Welcome to', 'Documentation:',
                'Management:', 'Support:', 'Last login', 'sudo su'
            ]
            
            for line in lines:
                # Skip cn/expect artifacts
                if any(p in line for p in skip_patterns):
                    continue
                # Skip prompts
                if 'master@' in line or 'root@' in line:
                    continue
                # Skip the command echo itself
                if command in line:
                    continue
                # Keep actual output
                if line.strip():
                    cleaned.append(line)
            
            result['stdout'] = '\n'.join(cleaned)
            result['stderr'] = stderr_output
            result['exit_code'] = exit_code
            result['success'] = len(result['stdout']) > 0
            
            if result['success']:
                self.audit.log('INFO', f'Command successful on {target_host}')
            else:
                self.audit.log('WARNING', f'No output from command on {target_host}')
            
        except Exception as e:
            result['error_message'] = str(e)
            self.audit.log('ERROR', f'Command failed: {e}')
        finally:
            if ssh_client:
                ssh_client.close()
            result['execution_time'] = round(time.time() - start_time, 2)
        
        return result
    
    def test_connectivity(self, hostname: str) -> bool:
        """Test if host is reachable via jumpserver"""
        result = self.execute_single_diagnostic(hostname, "echo 'test'")
        return result['success']
