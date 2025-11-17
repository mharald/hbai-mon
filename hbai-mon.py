#!/usr/bin/env python3
"""
HBAI-MON - Home Boehmecke AI Monitoring System
Automated infrastructure monitoring with interactive AI diagnosis

Version: 3.0.0 - Streamlined Interactive AI Analysis
Author: Harald Boehmecke
"""

import sys
import os
import json
import configparser
import logging
import syslog
from datetime import datetime
from typing import List, Dict, Optional, Tuple
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
AUDIT_LOG_FILE = f"{CONFIG_DIR}/audit.log"

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
        
        # Query to get storage alerts over threshold
        # IMPORTANT: Filter out devices that are down (status = 0) or ignored
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
            AND d.hostname LIKE 'hbc%%'
            AND d.status = 1  -- ONLY UP HOSTS
            AND d.ignore = 0  -- NOT IGNORED
            AND d.disabled = 0  -- NOT DISABLED
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


class InteractiveDiagnostic:
    """Handles interactive diagnostic flow with AI"""
    
    def __init__(self, db_manager: DatabaseManager, audit_logger: AuditLogger):
        self.db = db_manager
        self.audit = audit_logger
        
        # Initialize AI analyzer
        ollama_config = dict(self.db.credentials['ollama_api'])
        self.ai = InteractiveAIAnalyzer(ollama_config, audit_logger)
        
        # Initialize command executor
        ssh_creds = dict(self.db.credentials['ssh_default'])
        self.executor = CommandExecutor(ssh_creds, audit_logger)
    
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
        max_iterations = 10  # Prevent infinite loops
        iteration = 0
        
        print(f"{Colors.OKCYAN}Starting AI-driven interactive diagnosis...{Colors.ENDC}\n")
        
        while iteration < max_iterations:
            iteration += 1
            
            # Get AI recommendation for next diagnostic command
            print(f"{Colors.OKBLUE}Requesting AI diagnostic recommendation...{Colors.ENDC}")
            ai_response = self.ai.get_next_diagnostic_command(
                problem_context, 
                conversation_history
            )
            
            if not ai_response['success']:
                print(f"{Colors.FAIL}AI analysis failed: {ai_response.get('error', 'Unknown error')}{Colors.ENDC}")
                self.audit.log('ERROR', f"AI analysis failed for {hostname}", 
                             {'error': ai_response.get('error')})
                break
            
            # Check if AI is done
            if ai_response.get('done', False):
                print(f"\n{Colors.OKGREEN}✓ AI diagnosis complete{Colors.ENDC}")
                
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
            
            # Get the proposed command
            command = ai_response.get('command')
            explanation = ai_response.get('explanation', 'No explanation provided')
            
            if not command:
                print(f"{Colors.WARNING}AI did not provide a command. Ending diagnosis.{Colors.ENDC}")
                break
            
            # Display AI's recommendation
            print(f"\n{Colors.BOLD}AI Recommendation:{Colors.ENDC}")
            print(f"  {Colors.OKCYAN}Command:{Colors.ENDC} {command}")
            print(f"  {Colors.OKCYAN}Purpose:{Colors.ENDC} {explanation}")
            
            # Ask user for permission
            print(f"\n{Colors.BOLD}Execute this command? (y/n/s=skip to next alert): {Colors.ENDC}", end='')
            user_input = input().strip().lower()
            
            if user_input == 's':
                print(f"{Colors.WARNING}Skipping to next alert...{Colors.ENDC}")
                self.audit.log_ai_interaction('COMMAND_SKIPPED', hostname, command=command)
                return False
            elif user_input != 'y':
                print(f"{Colors.WARNING}Command rejected. Requesting alternative...{Colors.ENDC}")
                conversation_history.append({
                    'command': command,
                    'executed': False,
                    'reason': 'User rejected command'
                })
                self.audit.log_ai_interaction('COMMAND_REJECTED', hostname, 
                                             command=command, approved=False)
                continue
            
            # Execute the command
            print(f"{Colors.OKCYAN}Executing command...{Colors.ENDC}")
            self.audit.log_ai_interaction('COMMAND_APPROVED', hostname, 
                                         command=command, approved=True)
            
            result = self.executor.execute_single_diagnostic(hostname, command)
            
            # Display result summary
            if result['success']:
                print(f"{Colors.OKGREEN}✓ Command executed successfully{Colors.ENDC}")
                if result['stdout']:
                    # Show first 20 lines of output
                    lines = result['stdout'].split('\n')[:20]
                    print(f"\n{Colors.BOLD}Output:{Colors.ENDC}")
                    for line in lines:
                        print(f"  {line}")
                    if len(result['stdout'].split('\n')) > 20:
                        print(f"  {Colors.OKBLUE}... (truncated){Colors.ENDC}")
            else:
                print(f"{Colors.FAIL}✗ Command failed{Colors.ENDC}")
                if result.get('error_message'):
                    print(f"  Error: {result['error_message']}")
            
            # Add to conversation history
            conversation_history.append({
                'command': command,
                'executed': True,
                'stdout': result.get('stdout', ''),
                'stderr': result.get('stderr', ''),
                'exit_code': result.get('exit_code', -1),
                'success': result['success']
            })
            
            self.audit.log_ai_interaction('COMMAND_EXECUTED', hostname, 
                                         command=command,
                                         response=f"success={result['success']}")
        
        print(f"\n{Colors.HEADER}{'='*80}{Colors.ENDC}")
        return True
    
    def run(self):
        """Main execution flow"""
        print(f"""
{Colors.HEADER}╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║   {Colors.BOLD}HBAI-MON{Colors.ENDC}{Colors.HEADER} - Automated Disk Space Monitoring            ║
║   Version 3.0 - Interactive AI Diagnosis                     ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝{Colors.ENDC}
        """)
        
        self.audit.log('INFO', 'HBAI-MON started', {'user': os.getenv('USER', 'unknown')})
        
        # Get disk alerts (automatically excludes down hosts)
        print(f"{Colors.OKCYAN}Scanning for disk issues (excluding down hosts)...{Colors.ENDC}\n")
        alerts = self.db.get_disk_alerts()
        
        if not alerts:
            print(f"{Colors.OKGREEN}✓ No disk issues found (or all issues are on down hosts){Colors.ENDC}")
            self.audit.log('INFO', 'No disk issues found')
            return
        
        print(f"Found {Colors.WARNING}{len(alerts)}{Colors.ENDC} disk issues:\n")
        for alert in alerts:
            print(f"  • {alert['hostname']}:{alert['storage_descr']} - "
                  f"{Colors.WARNING}{alert['storage_perc']}%{Colors.ENDC}")
        
        # Process each alert interactively
        for i, alert in enumerate(alerts, 1):
            print(f"\n{Colors.BOLD}[{i}/{len(alerts)}] Processing alert {i} of {len(alerts)}{Colors.ENDC}")
            
            try:
                should_continue = self.process_alert(alert)
                if not should_continue:
                    print(f"\n{Colors.WARNING}Alert skipped by user{Colors.ENDC}")
            except KeyboardInterrupt:
                print(f"\n\n{Colors.WARNING}Interrupted by user{Colors.ENDC}")
                self.audit.log('INFO', 'HBAI-MON interrupted by user')
                break
            except Exception as e:
                print(f"\n{Colors.FAIL}Error processing alert: {e}{Colors.ENDC}")
                self.audit.log('ERROR', f'Error processing alert for {alert["hostname"]}', 
                             {'error': str(e)})
                continue
        
        print(f"\n{Colors.OKGREEN}✓ All alerts processed{Colors.ENDC}")
        self.audit.log('INFO', 'HBAI-MON completed')
        print(f"\nAudit log: {AUDIT_LOG_FILE}")


def main():
    """Main entry point"""
    # Initialize audit logger
    audit = AuditLogger(AUDIT_LOG_FILE)
    
    # Check if credentials file exists
    if not os.path.exists(CREDENTIALS_FILE):
        print(f"{Colors.FAIL}Error: Credentials file not found at {CREDENTIALS_FILE}{Colors.ENDC}")
        audit.log('ERROR', 'Credentials file not found', {'path': CREDENTIALS_FILE})
        sys.exit(1)
    
    try:
        # Initialize database manager
        db_manager = DatabaseManager(CREDENTIALS_FILE, audit)
        
        # Run interactive diagnostic
        diagnostic = InteractiveDiagnostic(db_manager, audit)
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
