#!/usr/bin/env python3
"""
Command Executor Module for HBAI-MON v3
Handles SSH connections through jumpserver with interactive cn script
"""

import paramiko
import time
import socket
from typing import Dict, Optional


class CommandExecutor:
    """Execute commands via SSH through jumpserver"""
    
    def __init__(self, ssh_config: dict, audit_logger):
        self.jumpserver = ssh_config.get('jumpserver', 'hbcsrv14')
        self.jumpserver_user = ssh_config.get('jumpserver_user', 'master')
        self.jumpserver_key = ssh_config.get('key_file', '/root/.ssh/id_rsa')
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
            # Connect to jumpserver
            ssh_client = paramiko.SSHClient()
            ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            self.audit.log('DEBUG', f'Connecting to {self.jumpserver} as {self.jumpserver_user}')
            
            # Connect to jumpserver
            ssh_client.connect(
                hostname=self.jumpserver,
                username=self.jumpserver_user,
                key_filename=self.jumpserver_key,
                timeout=self.timeout,
                look_for_keys=True,
                allow_agent=True
            )
            
            self.audit.log('INFO', f'Connected to {self.jumpserver}')
            
            # Extract just the hostname without domain if present
            target_host = hostname.split('.')[0] if '.' in hostname else hostname
            
            # For complex commands with pipes, we need to escape them properly
            # and wrap in bash -c to ensure proper execution
            if '|' in command or '>' in command or ';' in command:
                # Escape single quotes in command and wrap in bash -c
                escaped_cmd = command.replace("'", "'\\''")
                exec_command = f"bash -c '{escaped_cmd}'"
            else:
                exec_command = command
            
            # Create expect script that handles command execution
            expect_script = f'''#!/usr/bin/expect -f
set timeout 120
log_user 1

# Start cn to target host
spawn cn {target_host}

# Variable to track if we got to the prompt
set connected 0

# Handle connection
expect {{
#    "password:" {{
#        # Wait for password to be handled by cn
#        exp_continue
#    }}
    -re "(master|root)@{target_host}" {{
        set connected 1
        # Check if we need sudo
        if {{[string match "*master@*" $expect_out(0,string)]}} {{
            send "sudo su\\r"
            expect -re "root@{target_host}"
        }}
    }}
    timeout {{
        puts "ERROR: Connection timeout"
        exit 1
    }}
}}

# Make sure we're connected
if {{$connected == 0}} {{
    puts "ERROR: Failed to connect"
    exit 1
}}
sleep 10
# Execute the command
send "{exec_command}\\r"

# Wait for command to complete and return to prompt
set timeout 60
expect {{
    -re "root@{target_host}.*#" {{
        # Command completed
    }}
    timeout {{
        puts "WARNING: Command timeout - output may be incomplete"
    }}
}}

# Exit cleanly
send "exit\\r"
expect {{
    "master@{target_host}" {{
        send "exit\\r"
    }}
    eof {{}}
    timeout {{}}
}}

expect eof
'''
            
            # Write expect script to temp file
            temp_script_name = f"/tmp/cn_exec_{int(time.time())}.expect"
            write_script_cmd = f"cat > {temp_script_name} << 'EOFSCRIPT'\n{expect_script}\nEOFSCRIPT"
            
            # Write the expect script
            stdin, stdout, stderr = ssh_client.exec_command(write_script_cmd)
            stdout.read()  # Wait for completion
            
            # Make it executable
            ssh_client.exec_command(f"chmod +x {temp_script_name}")
            
            # Execute the expect script and capture output
            self.audit.log('DEBUG', f'Executing command on {target_host}: {command[:100]}...')
            
            stdin, stdout, stderr = ssh_client.exec_command(
                f"expect -f {temp_script_name} 2>&1",
                timeout=max(self.timeout * 3, 180)  # Give plenty of time
            )
            
            # Get raw output
            raw_output = stdout.read().decode('utf-8', errors='replace')
            exit_code = stdout.channel.recv_exit_status()
            
            # Clean up temp script
            try:
                ssh_client.exec_command(f"rm -f {temp_script_name}")
            except:
                pass  # Don't fail if cleanup fails
            
            # Process and clean the output
            lines = raw_output.split('\n')
            output_lines = []
            capture = False
            
            for line in lines:
                # Start capturing after we see the command being executed
                if exec_command in line or command in line:
                    capture = True
                    continue
                    
                # Stop at the next prompt or exit
                if capture:
                    if 'root@' in line and '#' in line:
                        break
                    if 'master@' in line:
                        break
                    if line.strip() == 'exit':
                        break
                    if 'ERROR:' in line or 'WARNING:' in line:
                        if 'ERROR:' in line:
                            result['error_message'] = line
                        continue
                        
                    output_lines.append(line)
            
            # Join output, removing empty lines at start/end
            result['stdout'] = '\n'.join(output_lines).strip()
            
            # Determine success
            # Consider successful if we got output and no ERROR messages
            has_output = len(result['stdout']) > 10  # More than trivial output
            no_connection_error = 'ERROR: Connection timeout' not in raw_output and 'ERROR: Failed to connect' not in raw_output
            
            result['success'] = has_output and no_connection_error
            result['exit_code'] = 0 if result['success'] else exit_code
            
            if result['success']:
                self.audit.log('INFO', f'Command executed successfully on {target_host}')
            else:
                self.audit.log('WARNING', f'Command may have failed on {target_host}', {
                    'has_output': has_output,
                    'output_length': len(result['stdout']),
                    'error': result.get('error_message', 'Unknown')
                })
                
                # If no output but no error either, provide a message
                if not has_output and no_connection_error:
                    result['stdout'] = '(No output returned from command)'
            
        except Exception as e:
            result['error_message'] = f"Execution error: {str(e)}"
            self.audit.log('ERROR', 'Command execution failed', {
                'error': str(e),
                'hostname': hostname,
                'command': command[:100]
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
