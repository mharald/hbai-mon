#!/usr/bin/env python3
"""
HBAI-MON - Home Boehmecke AI Monitoring System
Automated infrastructure monitoring with interactive AI diagnosis

Version: 3.1.0 - Multi-host diagnosis with infrastructure awareness
Author: Harald Boehmecke
"""

import sys
import os
import json
import configparser
import logging
import syslog
from datetime import datetime
from typing import List, Dict, Optional
import mysql.connector
from mysql.connector import Error
import time

# Add module path
sys.path.insert(0, '/etc/hbai-mon')
from hbai_executor import CommandExecutor
from hbai_ollama import InteractiveAIAnalyzer

# Configuration paths
CONFIG_DIR = "/etc/hbai-mon"
CREDENTIALS_FILE = f"{CONFIG_DIR}/.credentials"
AI_CONFIG_FILE = f"{CONFIG_DIR}/ai.conf"
AUDIT_LOG_FILE = f"{CONFIG_DIR}/audit.log"
INFRASTRUCTURE_FILE = f"{CONFIG_DIR}/infrastructure.txt"


class Colors:
    """ANSI color codes for terminal output"""
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


class AuditLogger:
    """Handles audit logging for AI interactions"""

    def __init__(self, log_file: str):
        # Ensure log directory exists
        log_dir = os.path.dirname(log_file)
        if log_dir and not os.path.exists(log_dir):
            os.makedirs(log_dir, exist_ok=True)

        # Configure file logger
        self.file_logger = logging.getLogger('hbai_audit')
        self.file_logger.setLevel(logging.INFO)

        # Create file handler
        file_handler = logging.FileHandler(log_file)
        file_format = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        file_handler.setFormatter(file_format)
        self.file_logger.addHandler(file_handler)

        # Also log to syslog
        syslog.openlog("hbai-mon", syslog.LOG_PID, syslog.LOG_LOCAL0)

    def log(self, level: str, message: str, details: dict = None):
        """Log an audit event"""
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'level': level,
            'message': message,
            'details': details or {}
        }

        # Log to file
        log_str = json.dumps(log_entry)
        if level == 'ERROR':
            self.file_logger.error(log_str)
            syslog.syslog(syslog.LOG_ERR, f"HBAI-MON: {message}")
        elif level == 'WARNING':
            self.file_logger.warning(log_str)
            syslog.syslog(syslog.LOG_WARNING, f"HBAI-MON: {message}")
        else:
            self.file_logger.info(log_str)
            syslog.syslog(syslog.LOG_INFO, f"HBAI-MON: {message}")

    def log_ai_interaction(self, action: str, hostname: str, command: str = None,
                           response: str = None, approved: bool = None):
        """Log AI interaction details"""
        details = {
            'action': action,
            'hostname': hostname,
            'command': command,
            'response_length': len(response) if response else 0,
            'approved': approved,
            'user': os.getenv('USER', 'unknown')
        }
        self.log('INFO', f"AI_{action}: {hostname}", details)


class DatabaseManager:
    """Handles all database connections and queries"""

    def __init__(self, credentials_file: str, audit_logger: AuditLogger):
        self.credentials = self._load_credentials(credentials_file)
        self.conn_observium = None
        self.conn_hbai = None
        self.audit = audit_logger

    def _load_credentials(self, filepath: str) -> configparser.ConfigParser:
        """Load credentials from INI file"""
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Credentials file not found: {filepath}")

        config = configparser.ConfigParser()
        config.read(filepath)
        return config

    def connect_observium(self) -> mysql.connector.MySQLConnection:
        """Connect to Observium database"""
        try:
            creds = self.credentials['mysql_observium']
            self.conn_observium = mysql.connector.connect(
                host=creds['host'],
                port=int(creds['port']),
                user=creds['user'],
                password=creds['password'],
                database=creds['database']
            )
            return self.conn_observium
        except Error as e:
            self.audit.log('ERROR', 'Failed to connect to Observium DB', {'error': str(e)})
            raise Exception(f"Failed to connect to Observium DB: {e}")

    def connect_hbai(self) -> mysql.connector.MySQLConnection:
        """Connect to HBAI database"""
        try:
            creds = self.credentials['mysql_hbai']
            self.conn_hbai = mysql.connector.connect(
                host=creds['host'],
                port=int(creds['port']),
                user=creds['user'],
                password=creds['password'],
                database=creds['database']
            )
            return self.conn_hbai
        except Error as e:
            self.audit.log('ERROR', 'Failed to connect to HBAI DB', {'error': str(e)})
            raise Exception(f"Failed to connect to HBAI DB: {e}")

    def execute_query(self, connection: mysql.connector.MySQLConnection,
                     query: str, params: tuple = None,
                     fetch: bool = True) -> Optional[List]:
        """Execute a SQL query"""
        cursor = connection.cursor(dictionary=True)
        try:
            cursor.execute(query, params or ())
            if fetch:
                return cursor.fetchall()
            else:
                connection.commit()
                return None
        except Error as e:
            self.audit.log('ERROR', 'Database query failed', {'error': str(e)})
            return None
        finally:
            cursor.close()

    def get_disk_alerts(self, threshold: int = 80) -> List[Dict]:
        """Fetch disk alerts from Observium - EXCLUDE DOWN HOSTS"""
        conn = self.connect_observium()

        query = """
        SELECT
            s.storage_id,
            s.device_id,
            d.hostname,
            d.status as device_status,
            s.storage_descr,
            s.storage_perc,
            s.storage_size,
            s.storage_used,
            s.storage_free
        FROM storage s
        JOIN devices d ON s.device_id = d.device_id
        WHERE s.storage_perc >= %s
            AND d.hostname LIKE 'hb%%'
            AND d.status = 1
            AND d.ignore = 0
            AND d.disabled = 0
            AND s.storage_ignore = 0
            AND s.storage_deleted = 0
            AND s.storage_type = 'hrStorageFixedDisk'
            AND s.storage_descr NOT LIKE '/proc%%'
            AND s.storage_descr NOT LIKE '/sys%%'
            AND s.storage_descr NOT LIKE '/dev%%'
            AND s.storage_descr NOT LIKE '/run%%'
        ORDER BY s.storage_perc DESC
        """

        results = self.execute_query(conn, query, (threshold,))

        if results:
            self.audit.log('INFO', f'Found {len(results)} disk alerts above {threshold}%')

        return results or []

    def close_all(self):
        """Close all database connections"""
        if self.conn_observium and self.conn_observium.is_connected():
            self.conn_observium.close()
        if self.conn_hbai and self.conn_hbai.is_connected():
            self.conn_hbai.close()


class InfrastructureInfo:
    """Parses and provides infrastructure information"""

    def __init__(self, infrastructure_file: str):
        self.hosts = {}
        self.jumpserver = None
        self._load(infrastructure_file)

    def _load(self, filepath: str):
        """Load and parse infrastructure file"""
        if not os.path.exists(filepath):
            return

        with open(filepath, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue

                parts = [p.strip() for p in line.split('|')]
                if len(parts) >= 3:
                    hostname = parts[0]
                    host_type = parts[1]
                    role = parts[2]
                    notes = parts[3] if len(parts) > 3 else ''

                    self.hosts[hostname] = {
                        'type': host_type,
                        'role': role,
                        'notes': notes
                    }

                    if role == 'jumpserver':
                        self.jumpserver = hostname

    def needs_jumpserver(self, hostname: str) -> bool:
        """Check if host requires jumpserver access"""
        if hostname not in self.hosts:
            return False

        host_type = self.hosts[hostname]['type']
        return host_type in ('nas', 'switch', 'appliance')

    def get_host_info(self, hostname: str) -> Optional[Dict]:
        """Get info about a host"""
        return self.hosts.get(hostname)

    def resolve_short_hostname(self, short_name: str) -> Optional[str]:
        """Resolve short hostname to FQDN"""
        # Direct match
        if short_name in self.hosts:
            return short_name

        # Try adding domain
        fqdn = f"{short_name}.internal.boehmecke.org"
        if fqdn in self.hosts:
            return fqdn

        # Search for partial match
        for hostname in self.hosts:
            if hostname.startswith(short_name + '.'):
                return hostname

        return None


def load_ai_config(config_file: str, credentials_file: str) -> Dict[str, str]:
    """Load AI configuration from ai.conf and merge with API key from credentials"""
    if not os.path.exists(config_file):
        raise FileNotFoundError(f"AI configuration file not found: {config_file}")
    
    if not os.path.exists(credentials_file):
        raise FileNotFoundError(f"Credentials file not found: {credentials_file}")
    
    # Load ai.conf
    config = configparser.ConfigParser()
    config.read(config_file)
    
    if 'ollama' not in config:
        raise ValueError(f"[ollama] section missing in {config_file}")
    
    ai_config = dict(config['ollama'])
    
    # Load API key from credentials
    creds = configparser.ConfigParser()
    creds.read(credentials_file)
    
    if 'ollama_api' not in creds:
        raise ValueError(f"[ollama_api] section missing in {credentials_file}")
    
    if 'key' not in creds['ollama_api']:
        raise ValueError(f"'key' field missing in [ollama_api] section of {credentials_file}")
    
    # Merge: add API key from credentials
    ai_config['key'] = creds['ollama_api']['key']
    
    # Convert numeric strings to proper types for convenience
    if 'timeout' in ai_config:
        ai_config['timeout'] = int(ai_config['timeout'])
    if 'min_commands_required' in ai_config:
        ai_config['min_commands_required'] = int(ai_config['min_commands_required'])
    if 'temperature' in ai_config:
        ai_config['temperature'] = float(ai_config['temperature'])
    if 'num_ctx' in ai_config:
        ai_config['num_ctx'] = int(ai_config['num_ctx'])
    if 'num_predict' in ai_config:
        ai_config['num_predict'] = int(ai_config['num_predict'])
    if 'top_p' in ai_config:
        ai_config['top_p'] = float(ai_config['top_p'])
    if 'top_k' in ai_config:
        ai_config['top_k'] = int(ai_config['top_k'])
    if 'repeat_penalty' in ai_config:
        ai_config['repeat_penalty'] = float(ai_config['repeat_penalty'])
    
    return ai_config

class InteractiveDiagnostic:
    """Handles interactive diagnostic flow with AI"""

    def __init__(self, db_manager: DatabaseManager, audit_logger: AuditLogger, ai_config: Dict[str, str]):
        self.db = db_manager
        self.audit = audit_logger

        # Initialize AI analyzer with merged config
        self.ai = InteractiveAIAnalyzer(ai_config, audit_logger)

        # Initialize command executor
        ssh_creds = dict(self.db.credentials['ssh_default'])
        self.executor = CommandExecutor(ssh_creds, audit_logger, CREDENTIALS_FILE)

        # Load infrastructure info
        self.infra = InfrastructureInfo(INFRASTRUCTURE_FILE)

    def process_alert(self, alert: Dict) -> bool:
        """Process a single disk alert interactively with AI"""
        hostname = alert['hostname']
        mount_point = alert['storage_descr']
        usage_perc = alert['storage_perc']
        used_gb = alert['storage_used'] / (1024**3) if alert['storage_used'] else 0
        total_gb = alert['storage_size'] / (1024**3) if alert['storage_size'] else 0
        free_gb = total_gb - used_gb

        print(f"\n{Colors.HEADER}{'='*80}{Colors.ENDC}")
        print(f"{Colors.BOLD}Processing Alert: {hostname}:{mount_point}{Colors.ENDC}")
        print(f"  Usage: {Colors.WARNING}{usage_perc}%{Colors.ENDC} ({used_gb:.1f}GB used of {total_gb:.1f}GB)")
        print(f"{Colors.HEADER}{'='*80}{Colors.ENDC}\n")

        self.audit.log_ai_interaction('ALERT_START', hostname,
                                      command=f"disk:{mount_point}",
                                      response=f"{usage_perc}% full")

        # Initial problem context
        problem_context = {
            'hostname': hostname,
            'mount_point': mount_point,
            'usage_percent': usage_perc,
            'used_gb': round(used_gb, 2),
            'total_gb': round(total_gb, 2),
            'free_gb': round(free_gb, 2)
        }

        # Start interactive diagnosis
        conversation_history = []
        max_iterations = 50
        iteration = 0

        print(f"{Colors.OKCYAN}Starting AI-driven interactive diagnosis (max {max_iterations} commands)...{Colors.ENDC}\n")

        while iteration < max_iterations:
            iteration += 1

            # Get AI recommendation
            print(f"{Colors.OKBLUE}[{iteration}/{max_iterations}] Requesting AI diagnostic recommendation...{Colors.ENDC}")
            ai_response = self.ai.get_next_diagnostic_command(
                problem_context,
                conversation_history
            )

            if not ai_response['success']:
                print(f"{Colors.FAIL}AI analysis failed: {ai_response.get('error', 'Unknown error')}{Colors.ENDC}")
                if ai_response.get('raw_response'):
                    print(f"{Colors.WARNING}Raw response: {ai_response['raw_response'][:200]}...{Colors.ENDC}")
                self.audit.log('ERROR', f"AI analysis failed for {hostname}",
                             {'error': ai_response.get('error')})
                break

            # Check if AI is done
            if ai_response.get('done', False):
                print(f"\n{Colors.OKGREEN}{'='*80}{Colors.ENDC}")
                print(f"{Colors.OKGREEN}✓ AI diagnosis complete after {iteration-1} commands{Colors.ENDC}")
                print(f"{Colors.OKGREEN}{'='*80}{Colors.ENDC}")

                # Display final analysis
                if ai_response.get('final_analysis'):
                    print(f"\n{Colors.BOLD}Final Analysis:{Colors.ENDC}")
                    print(ai_response['final_analysis'])

                if ai_response.get('recommended_actions'):
                    print(f"\n{Colors.BOLD}Recommended Actions:{Colors.ENDC}")
                    for i, action in enumerate(ai_response['recommended_actions'], 1):
                        print(f"  {i}. {action}")

                self.audit.log_ai_interaction('DIAGNOSIS_COMPLETE', hostname,
                                             response=ai_response.get('final_analysis', ''))
                break

            # Get the proposed command and target
            command = ai_response.get('command')
            target_host = ai_response.get('target_host', hostname)
            explanation = ai_response.get('explanation', 'No explanation provided')

            if not command:
                print(f"{Colors.WARNING}AI did not provide a command. Ending diagnosis.{Colors.ENDC}")
                break

            # Resolve target host if needed
            if target_host and not target_host.endswith('.internal.boehmecke.org'):
                resolved = self.infra.resolve_short_hostname(target_host)
                if resolved:
                    target_host = resolved
                else:
                    # Default to alerting host if can't resolve
                    print(f"{Colors.WARNING}Could not resolve host '{target_host}', using {hostname}{Colors.ENDC}")
                    target_host = hostname

            # Display AI's recommendation
            print(f"\n{Colors.BOLD}AI Recommendation:{Colors.ENDC}")
            print(f"  {Colors.OKCYAN}Target:{Colors.ENDC}  {target_host}")
            print(f"  {Colors.OKCYAN}Command:{Colors.ENDC} {command}")
            print(f"  {Colors.OKCYAN}Purpose:{Colors.ENDC} {explanation}")

            # Ask user for permission
            print(f"\n{Colors.BOLD}Execute this command? (y/n/s=skip alert/q=quit): {Colors.ENDC}", end='')
            user_input = input().strip().lower()

            if user_input == 'q':
                print(f"{Colors.WARNING}Quitting diagnosis...{Colors.ENDC}")
                self.audit.log_ai_interaction('DIAGNOSIS_QUIT', hostname)
                return False
            elif user_input == 's':
                print(f"{Colors.WARNING}Skipping to next alert...{Colors.ENDC}")
                self.audit.log_ai_interaction('COMMAND_SKIPPED', hostname, command=command)
                return False
            elif user_input != 'y':
                print(f"{Colors.WARNING}Command rejected. Requesting alternative...{Colors.ENDC}")
                conversation_history.append({
                    'command': command,
                    'target_host': target_host,
                    'executed': False,
                    'reason': 'User rejected command'
                })
                self.audit.log_ai_interaction('COMMAND_REJECTED', hostname,
                                             command=command, approved=False)
                continue

            # Execute the command (all commands go through cn script on jumpserver)
            print(f"{Colors.OKCYAN}Executing command on {target_host}...{Colors.ENDC}")
            self.audit.log_ai_interaction('COMMAND_APPROVED', target_host,
                                         command=command, approved=True)

            result = self.executor.execute_single_diagnostic(target_host, command)

            # Display result summary
            if result['success']:
                print(f"{Colors.OKGREEN}✓ Command executed successfully{Colors.ENDC}")
                if result['stdout']:
                    lines = result['stdout'].split('\n')[:20]
                    print(f"\n{Colors.BOLD}Output:{Colors.ENDC}")
                    for line in lines:
                        print(f"  {line}")
                    if len(result['stdout'].split('\n')) > 20:
                        print(f"  {Colors.OKBLUE}... (truncated, {len(result['stdout'].split(chr(10)))} lines total){Colors.ENDC}")
            else:
                print(f"{Colors.FAIL}✗ Command failed{Colors.ENDC}")
                if result.get('error_message'):
                    print(f"  Error: {result['error_message']}")

                if not result.get('stdout'):
                    result['stdout'] = f"Command failed: {result.get('error_message', 'Unknown error')}"

            # Add to conversation history
            conversation_history.append({
                'command': command,
                'target_host': target_host,
                'executed': True,
                'stdout': result.get('stdout', ''),
                'stderr': result.get('stderr', ''),
                'exit_code': result.get('exit_code', -1),
                'success': result['success']
            })

            # Show progress
            print(f"\n{Colors.OKBLUE}[Progress] {len([h for h in conversation_history if h.get('executed')])} commands executed{Colors.ENDC}")

            self.audit.log_ai_interaction('COMMAND_EXECUTED', target_host,
                                         command=command,
                                         response=f"success={result['success']}")

        if iteration >= max_iterations:
            print(f"\n{Colors.WARNING}Reached maximum iterations ({max_iterations}). Ending diagnosis.{Colors.ENDC}")
            self.audit.log('WARNING', f'Max iterations reached for {hostname}')

        print(f"\n{Colors.HEADER}{'='*80}{Colors.ENDC}")
        return True

    def run(self):
        """Main execution flow"""
        print(f"""
{Colors.HEADER}╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║   {Colors.BOLD}HBAI-MON{Colors.ENDC}{Colors.HEADER} - Automated Disk Space Monitoring            ║
║   Version 3.1.0 - Multi-host AI Diagnosis                    ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝{Colors.ENDC}
        """)

        self.audit.log('INFO', 'HBAI-MON started', {'user': os.getenv('USER', 'unknown')})

        # Check infrastructure file
        if not os.path.exists(INFRASTRUCTURE_FILE):
            print(f"{Colors.WARNING}⚠ Infrastructure file not found: {INFRASTRUCTURE_FILE}{Colors.ENDC}")
            print(f"{Colors.WARNING}  AI will have limited context about your infrastructure.{Colors.ENDC}\n")

        # Get disk alerts
        print(f"{Colors.OKCYAN}Scanning for disk issues (excluding down hosts)...{Colors.ENDC}\n")
        alerts = self.db.get_disk_alerts()

        if not alerts:
            print(f"{Colors.OKGREEN}✓ No disk issues found{Colors.ENDC}")
            self.audit.log('INFO', 'No disk issues found')
            return

        print(f"Found {Colors.WARNING}{len(alerts)}{Colors.ENDC} disk issues:\n")
        for i, alert in enumerate(alerts, 1):
            print(f"  {i}. {alert['hostname']}:{alert['storage_descr']} - "
                  f"{Colors.WARNING}{alert['storage_perc']}%{Colors.ENDC}")

        print()  # Empty line before processing

        # Process each alert
        for i, alert in enumerate(alerts, 1):
            print(f"\n{Colors.BOLD}[Alert {i}/{len(alerts)}]{Colors.ENDC}")

            try:
                should_continue = self.process_alert(alert)
                if not should_continue:
                    # Check if user wants to continue to next alert or quit entirely
                    if i < len(alerts):
                        print(f"\n{Colors.BOLD}Continue to next alert? (y/n): {Colors.ENDC}", end='')
                        if input().strip().lower() != 'y':
                            print(f"{Colors.WARNING}Exiting...{Colors.ENDC}")
                            break
            except KeyboardInterrupt:
                print(f"\n\n{Colors.WARNING}Interrupted by user{Colors.ENDC}")
                self.audit.log('INFO', 'HBAI-MON interrupted by user')
                break
            except Exception as e:
                print(f"\n{Colors.FAIL}Error processing alert: {e}{Colors.ENDC}")
                self.audit.log('ERROR', f'Error processing alert for {alert["hostname"]}',
                             {'error': str(e)})
                import traceback
                traceback.print_exc()
                continue

        print(f"\n{Colors.OKGREEN}✓ Session complete{Colors.ENDC}")
        self.audit.log('INFO', 'HBAI-MON completed')
        print(f"\nAudit log: {AUDIT_LOG_FILE}")


def main():
    """Main entry point"""
    # Create audit logger (will create directory if needed)
    audit = AuditLogger(AUDIT_LOG_FILE)

    # Check for credentials file
    if not os.path.exists(CREDENTIALS_FILE):
        print(f"{Colors.FAIL}Error: Credentials file not found at {CREDENTIALS_FILE}{Colors.ENDC}")
        audit.log('ERROR', 'Credentials file not found', {'path': CREDENTIALS_FILE})
        sys.exit(1)

    # Load AI configuration (merges ai.conf + API key from credentials)
    try:
        ai_config = load_ai_config(AI_CONFIG_FILE, CREDENTIALS_FILE)
        audit.log('INFO', 'AI configuration loaded', {
            'model': ai_config.get('model'),
            'min_commands': ai_config.get('min_commands_required', 10)
        })
    except Exception as e:
        print(f"{Colors.FAIL}Error loading AI configuration: {e}{Colors.ENDC}")
        audit.log('ERROR', 'Failed to load AI configuration', {'error': str(e)})
        sys.exit(1)

    try:
        db_manager = DatabaseManager(CREDENTIALS_FILE, audit)
        diagnostic = InteractiveDiagnostic(db_manager, audit, ai_config)
        diagnostic.run()

    except KeyboardInterrupt:
        print(f"\n\n{Colors.WARNING}Program interrupted{Colors.ENDC}")
        audit.log('INFO', 'Program interrupted by user')
    except Exception as e:
        print(f"\n{Colors.FAIL}Fatal error: {e}{Colors.ENDC}")
        audit.log('ERROR', 'Fatal error', {'error': str(e)})
        import traceback
        traceback.print_exc()
        sys.exit(1)
    finally:
        if 'db_manager' in locals():
            db_manager.close_all()


if __name__ == "__main__":
    main()
