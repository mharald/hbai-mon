#!/usr/bin/env python3
"""
Command Executor Module for HBAI-MON v3
Properly handles expect-based cn script with PTY allocation
"""

import subprocess
import time
from typing import Dict


class CommandExecutor:
    """Execute commands via cn script on jumpserver"""
    
    def __init__(self, ssh_config: dict, audit_logger):
        self.jumpserver = ssh_config.get('jumpserver', 'hbcsrv14')
        self.jumpserver_user = ssh_config.get('jumpserver_user', 'master')
        self.cn_script = 'cn'
        self.timeout = int(ssh_config.get('timeout', 120))  # 120s to be safe
        self.audit = audit_logger
    
    def execute_single_diagnostic(self, hostname: str, command: str) -> Dict:
        """Execute a single diagnostic command on target host via cn script on jumpserver"""
        
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
            
            self.audit.log('DEBUG', f'Executing on {target_host}: {command[:100]}')
            
            # Build SSH command with -t to force TTY allocation (needed for expect script)
            # The cn script expects: cn <hostname> <command parts...>
            ssh_cmd = [
                'ssh',
                '-t',  # Force TTY allocation for expect script
                '-o', 'LogLevel=ERROR',  # Suppress SSH warnings
                f'{self.jumpserver_user}@{self.jumpserver}',
                self.cn_script,
                target_host,
                command
            ]
            
            # Execute
            proc = subprocess.run(
                ssh_cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout
            )
            
            result['exit_code'] = proc.returncode
            
            # Clean up output - remove extra newlines the user noticed
            result['stdout'] = proc.stdout.strip()
            result['stderr'] = proc.stderr.strip()
            
            # Command is successful if we got output and exit code is 0
            result['success'] = (len(result['stdout']) > 0 and proc.returncode == 0)
            
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
